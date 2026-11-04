"""Google Safe Browsing Lookup API v4 Threat Intelligence Adapter."""

import time
import logging
import httpx
from app.core.config import settings
from app.services.threat_intelligence.base import (
    BaseThreatProvider,
    ThreatCheckResult,
    ProviderThreatStatus,
)

logger = logging.getLogger("smsshield.threat.safebrowsing")


class GoogleSafeBrowsingProvider(BaseThreatProvider):
    """
    Adapter for Google Safe Browsing Lookup API v4.
    Identifies malware, unwanted software, and social engineering (phishing).
    """

    LOOKUP_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    TIMEOUT_SECONDS = 3.0

    def provider_name(self) -> str:
        return "google_safe_browsing"

    def is_configured(self) -> bool:
        return bool(settings.GOOGLE_SAFE_BROWSING_API_KEY and settings.GOOGLE_SAFE_BROWSING_API_KEY.strip())

    async def check_url(self, url: str) -> ThreatCheckResult:
        if not self.is_configured():
            return ThreatCheckResult(
                provider=self.provider_name(),
                status=ProviderThreatStatus.UNCONFIGURED,
                message="Google Safe Browsing API key not configured in environment",
            )

        start_time = time.perf_counter()
        payload = {
            "client": {
                "clientId": "smsshield",
                "clientVersion": settings.VERSION,
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            async with httpx.AsyncClient(timeout=self.TIMEOUT_SECONDS) as client:
                response = await client.post(
                    f"{self.LOOKUP_URL}?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}",
                    json=payload,
                )

            latency_ms = int((time.perf_counter() - start_time) * 1000)

            if response.status_code != 200:
                logger.warning(f"Safe Browsing API returned HTTP {response.status_code}")
                return ThreatCheckResult(
                    provider=self.provider_name(),
                    status=ProviderThreatStatus.UNAVAILABLE,
                    latency_ms=latency_ms,
                    message=f"Safe Browsing API returned HTTP {response.status_code}",
                )

            data = response.json()
            matches = data.get("matches", [])

            if matches:
                threat_types = list(set(m.get("threatType", "MALICIOUS") for m in matches))
                return ThreatCheckResult(
                    provider=self.provider_name(),
                    status=ProviderThreatStatus.MALICIOUS,
                    threat_categories=threat_types,
                    latency_ms=latency_ms,
                    message=f"Google Safe Browsing flagged URL as: {', '.join(threat_types)}",
                    raw_details={"matches": matches},
                )
            else:
                return ThreatCheckResult(
                    provider=self.provider_name(),
                    status=ProviderThreatStatus.CLEAN,
                    latency_ms=latency_ms,
                    message="No threat matches found in Google Safe Browsing database",
                )

        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            logger.warning(f"Safe Browsing lookup failed: {exc}")
            return ThreatCheckResult(
                provider=self.provider_name(),
                status=ProviderThreatStatus.UNAVAILABLE,
                latency_ms=latency_ms,
                message="Google Safe Browsing query timed out or unreachable",
            )
        except Exception as exc:
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error(f"Unexpected Safe Browsing exception: {exc}")
            return ThreatCheckResult(
                provider=self.provider_name(),
                status=ProviderThreatStatus.UNAVAILABLE,
                latency_ms=latency_ms,
                message="Internal exception during Safe Browsing check",
            )
