"""Integration tests for URL and message scanning endpoints."""

import hashlib
import pytest
from unittest.mock import AsyncMock, patch
from sqlalchemy import select
from starlette.testclient import TestClient

from app.models.scan import ScanRecord, UrlScanResult, ThreatProviderResult
from app.core.database import SessionLocal
from app.services.threat_intelligence.base import ProviderThreatStatus, ThreatCheckResult


# ---------------------------------------------------------------------------
# URL Scan Endpoint Tests
# ---------------------------------------------------------------------------

def test_scan_url_benign(client: TestClient):
    """Verify scanning a clean URL returns benign status and persists sanitized record."""
    dummy_results = {
        "urlhaus": ThreatCheckResult(provider="urlhaus", status=ProviderThreatStatus.UNKNOWN),
        "google_safe_browsing": ThreatCheckResult(provider="google_safe_browsing", status=ProviderThreatStatus.CLEAN),
    }

    with patch(
        "app.api.v1.endpoints.scan_url.aggregator.check_url",
        new_callable=AsyncMock,
        return_value=(ProviderThreatStatus.CLEAN, dummy_results, ["Clean across sources"], 10.0),
    ):
        with patch("app.api.v1.endpoints.scan_url.validate_url_for_safe_inspection"):
            response = client.post("/api/v1/scan/url", json={"url": "https://example.com/welcome"})

    assert response.status_code == 200
    data = response.json()
    assert data["final_url_classification"] == "benign"
    assert data["risk_score"] == 10.0
    assert data["hostname"] == "example.com"
    assert "BENIGN" in data["recommendation"]

    # Verify database persistence
    with SessionLocal() as db:
        record = db.scalar(select(UrlScanResult).where(UrlScanResult.domain == "example.com"))
        assert record is not None
        assert record.classification == "benign"


def test_scan_url_malicious(client: TestClient):
    """Verify scanning a malicious URL flags it with high risk and persists providers."""
    dummy_results = {
        "urlhaus": ThreatCheckResult(
            provider="urlhaus",
            status=ProviderThreatStatus.MALICIOUS,
            threat_categories=["phishing"],
            reference_id="999888",
        )
    }

    with patch(
        "app.api.v1.endpoints.scan_url.aggregator.check_url",
        new_callable=AsyncMock,
        return_value=(ProviderThreatStatus.MALICIOUS, dummy_results, ["Confirmed malicious by Urlhaus"], 98.0),
    ):
        with patch("app.api.v1.endpoints.scan_url.validate_url_for_safe_inspection"):
            response = client.post("/api/v1/scan/url", json={"url": "https://fraud-sbi-portal.xyz/login"})

    assert response.status_code == 200
    data = response.json()
    assert data["final_url_classification"] == "malicious"
    assert data["risk_score"] >= 95.0
    assert any("Confirmed malicious" in r for r in data["evidence"])


def test_scan_url_unknown_indeterminate(client: TestClient):
    """NON-NEGOTIABLE RULE: When threat reports are absent/unknown, return UNKNOWN not BENIGN."""
    dummy_results = {
        "urlhaus": ThreatCheckResult(provider="urlhaus", status=ProviderThreatStatus.UNKNOWN),
        "google_safe_browsing": ThreatCheckResult(provider="google_safe_browsing", status=ProviderThreatStatus.UNCONFIGURED),
    }

    with patch(
        "app.api.v1.endpoints.scan_url.aggregator.check_url",
        new_callable=AsyncMock,
        return_value=(ProviderThreatStatus.UNKNOWN, dummy_results, ["No definitive match"], 50.0),
    ):
        with patch("app.api.v1.endpoints.scan_url.validate_url_for_safe_inspection"):
            response = client.post("/api/v1/scan/url", json={"url": "https://untracked-blog-site.org"})

    assert response.status_code == 200
    data = response.json()
    assert data["final_url_classification"] == "unknown"
    assert data["risk_score"] == 50.0
    assert "UNKNOWN REPUTATION" in data["recommendation"]


def test_scan_url_ssrf_blocked_localhost(client: TestClient):
    """Verify SSRF attempt targeting 127.0.0.1 is rejected with 400 Bad Request."""
    response = client.post("/api/v1/scan/url", json={"url": "http://127.0.0.1:8080/admin/secrets"})
    assert response.status_code == 400
    assert "SSRF Violation" in response.json()["detail"]


def test_scan_url_ssrf_blocked_cloud_metadata(client: TestClient):
    """Verify SSRF attempt targeting cloud metadata 169.254.169.254 is rejected with 400."""
    response = client.post("/api/v1/scan/url", json={"url": "http://169.254.169.254/latest/meta-data"})
    assert response.status_code == 400
    assert "SSRF Violation" in response.json()["detail"]


def test_scan_url_malformed_scheme_rejected(client: TestClient):
    """Verify non-HTTP schemes are rejected with 422 Unprocessable Entity."""
    response = client.post("/api/v1/scan/url", json={"url": "file:///etc/shadow"})
    assert response.status_code == 422
    assert "Malformed URL" in response.json()["detail"]


def test_scan_url_redacts_sensitive_query_parameters(client: TestClient):
    """Verify sensitive auth tokens in query string are redacted before DB storage."""
    dummy_results = {}
    with patch(
        "app.api.v1.endpoints.scan_url.aggregator.check_url",
        new_callable=AsyncMock,
        return_value=(ProviderThreatStatus.CLEAN, dummy_results, [], 10.0),
    ):
        with patch("app.api.v1.endpoints.scan_url.validate_url_for_safe_inspection"):
            response = client.post(
                "/api/v1/scan/url",
                json={"url": "https://secure-bank.com/reset?token=my_secret_token_12345&user=alice"},
            )

    assert response.status_code == 200
    data = response.json()
    assert "my_secret_token_12345" not in data["normalized_url"]

    # Check database record
    with SessionLocal() as db:
        record = db.scalar(select(UrlScanResult).where(UrlScanResult.domain == "secure-bank.com"))
        assert record is not None
        assert "my_secret_token_12345" not in record.normalized_url
        assert "[REDACTED]" in record.normalized_url or "%5BREDACTED%5D" in record.normalized_url


# ---------------------------------------------------------------------------
# Message Scan Endpoint Tests
# ---------------------------------------------------------------------------

def test_scan_message_phishing_scam(client: TestClient):
    """Verify urgent phishing SMS with bank lure and link is flagged as MALICIOUS."""
    msg = (
        "Dear customer, your SBI netbanking is blocked due to incomplete KYC! "
        "Update immediately at https://sbi-kyc-update.com/verify to avoid permanent suspension."
    )

    with patch(
        "app.api.v1.endpoints.scan_message.aggregator.check_url",
        new_callable=AsyncMock,
        return_value=(ProviderThreatStatus.MALICIOUS, {}, [], 98.0),
    ):
        with patch("app.api.v1.endpoints.scan_message.validate_url_for_safe_inspection"):
            response = client.post(
                "/api/v1/scan/message",
                json={
                    "message_text": msg,
                    "source_type": "manual_paste",
                    "source_package": None,
                },
            )

    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "MALICIOUS"
    assert data["risk_score"] >= 90.0
    assert len(data["reasons"]) > 0
    assert any("KYC" in r or "suspension" in r.lower() or "malicious" in r.lower() for r in data["reasons"])


def test_scan_message_benign(client: TestClient):
    """Verify regular non-scam conversational message is classified as SAFE."""
    msg = "Hi Dad, I will arrive at the train station around 6:00 PM. See you soon!"

    response = client.post(
        "/api/v1/scan/message",
        json={
            "message_text": msg,
            "source_type": "manual_paste",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "SAFE"
    assert data["risk_score"] <= 20.0
    assert len(data["extracted_urls"]) == 0


def test_scan_message_empty_fails_validation(client: TestClient):
    """Verify empty or whitespace-only messages are rejected with 422."""
    response = client.post("/api/v1/scan/message", json={"message_text": "   "})
    assert response.status_code == 422


def test_scan_message_zero_raw_text_storage_privacy(client: TestClient):
    """NON-NEGOTIABLE PRIVACY: Verify raw SMS message is NEVER persisted to database."""
    unique_canary = "CanarySensitiveText_XYZ_987654321"
    msg = f"Bank Alert: Your OTP is 123456. Do not share. Ref: {unique_canary}"
    expected_hash = hashlib.sha256(msg.strip().encode("utf-8")).hexdigest()

    response = client.post(
        "/api/v1/scan/message",
        json={"message_text": msg, "source_type": "notification_auto", "source_package": "com.google.android.apps.messaging"},
    )
    assert response.status_code == 200

    # Query DB to inspect raw columns of ScanRecord
    with SessionLocal() as db:
        record = db.scalar(select(ScanRecord).where(ScanRecord.message_hash == expected_hash))
        assert record is not None
        assert record.message_hash == expected_hash

        # Strict check: ensure unique canary text does not exist anywhere in the record
        assert unique_canary not in (record.source_category or "")
        assert unique_canary not in (record.source_package or "")
        assert unique_canary not in (record.classification or "")
        assert unique_canary not in (record.detection_reasons or "")
        assert unique_canary not in (record.recommendation or "")
        assert unique_canary not in (record.sms_model_version or "")

