"""Unit and integration tests for threat intelligence providers and aggregator."""

import pytest
import httpx
from unittest.mock import AsyncMock, patch, MagicMock

from app.core.config import settings
from app.services.threat_intelligence.base import (
    BaseThreatProvider,
    ThreatCheckResult,
    ProviderThreatStatus,
)
from app.services.threat_intelligence.urlhaus import URLhausProvider
from app.services.threat_intelligence.google_safe_browsing import GoogleSafeBrowsingProvider
from app.services.threat_intelligence.virustotal import VirusTotalProvider
from app.services.threat_intelligence.aggregator import ThreatAggregator


# ---------------------------------------------------------------------------
# URLhaus Provider Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_urlhaus_malicious_hit():
    """Verify URLhaus positive blacklist match returns MALICIOUS status."""
    provider = URLhausProvider()
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "query_status": "ok",
        "id": "123456",
        "url_status": "online",
        "threat": "malware_download",
        "tags": ["exe", "redline"],
    }

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        res = await provider.check_url("https://malware-drop.ru/payload.exe")

    assert res.status == ProviderThreatStatus.MALICIOUS
    assert res.reference_id == "123456"
    assert "malware_download" in res.threat_categories
    assert "redline" in res.threat_categories
    assert "Confirmed active malicious URL" in res.message


@pytest.mark.asyncio
async def test_urlhaus_no_results_returns_unknown():
    """STRICT PRIVACY/INTELLIGENCE RULE: Absence of report does NOT mean clean."""
    provider = URLhausProvider()
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"query_status": "no_results"}

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        res = await provider.check_url("https://unreported-new-domain.com")

    assert res.status == ProviderThreatStatus.UNKNOWN
    assert "threat status indeterminate" in res.message


@pytest.mark.asyncio
async def test_urlhaus_http_error_returns_unavailable():
    """Verify HTTP error from upstream service returns UNAVAILABLE."""
    provider = URLhausProvider()
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 503

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        res = await provider.check_url("https://test.com")

    assert res.status == ProviderThreatStatus.UNAVAILABLE
    assert "HTTP 503" in res.message


@pytest.mark.asyncio
async def test_urlhaus_timeout_returns_unavailable():
    """Verify network timeout returns UNAVAILABLE gracefully without throwing."""
    provider = URLhausProvider()

    with patch("httpx.AsyncClient.post", side_effect=httpx.TimeoutException("Read timed out")):
        res = await provider.check_url("https://slow-responding-host.com")

    assert res.status == ProviderThreatStatus.UNAVAILABLE
    assert "timed out" in res.message


# ---------------------------------------------------------------------------
# Google Safe Browsing Provider Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_gsb_unconfigured_when_no_api_key():
    """Verify provider signals UNCONFIGURED when no API key is supplied."""
    provider = GoogleSafeBrowsingProvider()
    with patch.object(settings, "GOOGLE_SAFE_BROWSING_API_KEY", ""):
        res = await provider.check_url("https://example.com")
        assert res.status == ProviderThreatStatus.UNCONFIGURED
        assert "not configured" in res.message


@pytest.mark.asyncio
async def test_gsb_malicious_match():
    """Verify threat match in Safe Browsing returns MALICIOUS."""
    provider = GoogleSafeBrowsingProvider()
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "matches": [
            {
                "threatType": "SOCIAL_ENGINEERING",
                "platformType": "ANY_PLATFORM",
                "threatEntryType": "URL",
            }
        ]
    }

    with patch.object(settings, "GOOGLE_SAFE_BROWSING_API_KEY", "dummy_test_key_123"):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            res = await provider.check_url("https://fake-sbi-login.com")

    assert res.status == ProviderThreatStatus.MALICIOUS
    assert "SOCIAL_ENGINEERING" in res.threat_categories


@pytest.mark.asyncio
async def test_gsb_clean_when_no_matches():
    """Verify Safe Browsing returns CLEAN when threat matches list is empty."""
    provider = GoogleSafeBrowsingProvider()
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {}  # Empty response means clean per GSB v4 spec

    with patch.object(settings, "GOOGLE_SAFE_BROWSING_API_KEY", "dummy_test_key_123"):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            res = await provider.check_url("https://trusted-bank.com")

    assert res.status == ProviderThreatStatus.CLEAN
    assert "No threat matches found" in res.message


# ---------------------------------------------------------------------------
# VirusTotal Provider Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_virustotal_unconfigured_when_no_key():
    """Verify VirusTotal returns UNCONFIGURED when key is omitted."""
    provider = VirusTotalProvider()
    with patch.object(settings, "VIRUSTOTAL_API_KEY", ""):
        res = await provider.check_url("https://example.com")
        assert res.status == ProviderThreatStatus.UNCONFIGURED


@pytest.mark.asyncio
async def test_virustotal_404_returns_unknown():
    """Verify 404 from VirusTotal (URL never analyzed before) maps to UNKNOWN."""
    provider = VirusTotalProvider()
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 404

    with patch.object(settings, "VIRUSTOTAL_API_KEY", "dummy_vt_key"):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            res = await provider.check_url("https://brand-new-domain.com")

    assert res.status == ProviderThreatStatus.UNKNOWN
    assert "not yet been analyzed" in res.message


@pytest.mark.asyncio
async def test_virustotal_multi_engine_malicious():
    """Verify >= 2 vendor hits flags URL as MALICIOUS."""
    provider = VirusTotalProvider()
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 8,
                    "suspicious": 1,
                    "harmless": 45,
                }
            }
        }
    }

    with patch.object(settings, "VIRUSTOTAL_API_KEY", "dummy_vt_key"):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            res = await provider.check_url("https://phishing-site.xyz")

    assert res.status == ProviderThreatStatus.MALICIOUS
    assert "flagged_by_8_antivirus_engines" in res.threat_categories


@pytest.mark.asyncio
async def test_virustotal_suspicious():
    """Verify 1 malicious or >= 2 suspicious flags URL as SUSPICIOUS."""
    provider = VirusTotalProvider()
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 1,
                    "harmless": 50,
                }
            }
        }
    }

    with patch.object(settings, "VIRUSTOTAL_API_KEY", "dummy_vt_key"):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            res = await provider.check_url("https://borderline-site.biz")

    assert res.status == ProviderThreatStatus.SUSPICIOUS


# ---------------------------------------------------------------------------
# ThreatAggregator Consensus Tests
# ---------------------------------------------------------------------------

class DummyProvider(BaseThreatProvider):
    def __init__(self, name: str, result_status: ProviderThreatStatus):
        self._name = name
        self._result_status = result_status

    def provider_name(self) -> str:
        return self._name

    def is_configured(self) -> bool:
        return True

    async def check_url(self, url: str) -> ThreatCheckResult:
        return ThreatCheckResult(
            provider=self._name,
            status=self._result_status,
            message=f"Status: {self._result_status.value}",
        )


@pytest.mark.asyncio
async def test_aggregator_malicious_overrides():
    """Verify that any MALICIOUS report causes the composite verdict to be MALICIOUS."""
    p1 = DummyProvider("prov1", ProviderThreatStatus.MALICIOUS)
    p2 = DummyProvider("prov2", ProviderThreatStatus.CLEAN)
    p3 = DummyProvider("prov3", ProviderThreatStatus.UNKNOWN)

    agg = ThreatAggregator(providers=[p1, p2, p3])
    status, results_map, evidence, score = await agg.check_url("https://target.com")

    assert status == ProviderThreatStatus.MALICIOUS
    assert score == 98.0
    assert any("Confirmed malicious" in e for e in evidence)


@pytest.mark.asyncio
async def test_aggregator_suspicious_verdict():
    """Verify that SUSPICIOUS verdict is reached when no malicious reports exist."""
    p1 = DummyProvider("prov1", ProviderThreatStatus.SUSPICIOUS)
    p2 = DummyProvider("prov2", ProviderThreatStatus.CLEAN)

    agg = ThreatAggregator(providers=[p1, p2])
    status, results_map, evidence, score = await agg.check_url("https://target.com")

    assert status == ProviderThreatStatus.SUSPICIOUS
    assert score == 65.0


@pytest.mark.asyncio
async def test_aggregator_all_unknown_yields_unknown():
    """NON-NEGOTIABLE RULE: When no positive or negative reports exist, status is UNKNOWN."""
    p1 = DummyProvider("urlhaus", ProviderThreatStatus.UNKNOWN)
    p2 = DummyProvider("safebrowsing", ProviderThreatStatus.UNCONFIGURED)
    p3 = DummyProvider("virustotal", ProviderThreatStatus.UNAVAILABLE)

    agg = ThreatAggregator(providers=[p1, p2, p3])
    status, results_map, evidence, score = await agg.check_url("https://unknown-domain.com")

    assert status == ProviderThreatStatus.UNKNOWN
    assert score == 50.0
    assert any("No definitive threat intelligence match" in e for e in evidence)


@pytest.mark.asyncio
async def test_aggregator_exception_isolation():
    """Verify that an unhandled exception in one provider does not crash the aggregator."""
    class BrokenProvider(BaseThreatProvider):
        def provider_name(self) -> str:
            return "broken"

        def is_configured(self) -> bool:
            return True

        async def check_url(self, url: str) -> ThreatCheckResult:
            raise RuntimeError("Catastrophic provider breakdown")

    p1 = BrokenProvider()
    p2 = DummyProvider("prov2", ProviderThreatStatus.CLEAN)

    agg = ThreatAggregator(providers=[p1, p2])
    status, results_map, evidence, score = await agg.check_url("https://target.com")

    assert "broken" in results_map
    assert results_map["broken"].status == ProviderThreatStatus.UNAVAILABLE
    assert status == ProviderThreatStatus.CLEAN
