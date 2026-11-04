"""URLhaus (abuse.ch) Threat Intelligence Provider Adapter."""

import time
import logging
import httpx
from app.services.threat_intelligence.base import (
    BaseThreatProvider,
    ThreatCheckResult,
    ProviderThreatStatus,
)

logger = logging.getLogger("smsshield.threat.urlhaus")


class URLhausProvider(BaseThreatProvider):
    """
    Adapter for abuse.ch URLhaus public API.
    A collaborative intelligence feed tracking active malware and phishing URLs.
    """

    API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
    TIMEOUT_SECONDS = 3.0

    def provider_name(self) -> str:
        return "urlhaus"

    def is_configured(self) -> bool:
        # Public API feed does not require mandatory private credentials
        return True

    async def check_url(self, url: str) -> ThreatCheckResult:
        start_time = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=self.TIMEOUT_SECONDS) as client:
                response = await client.post(
                    self.API_URL,
                    data={"url": url},
                    headers={"User-Agent": "SMSShield-SecurityBot/1.0"},
                )

            latency_ms = int((time.perf_counter() - start_time) * 1000)

            if response.status_code != 200:
                logger.warning(f"URLhaus returned unexpected HTTP {response.status_code}")
                return ThreatCheckResult(
                    provider=self.provider_name(),
                    status=ProviderThreatStatus.UNAVAILABLE,
                    latency_ms=latency_ms,
                    message=f"URLhaus service returned HTTP {response.status_code}",
                )

            data = response.json()
            query_status = data.get("query_status")

            if query_status == "ok":
                threat = data.get("threat", "malware_download")
                tags = data.get("tags") or []
                urlhaus_id = str(data.get("id")) if data.get("id") else None

                return ThreatCheckResult(
                    provider=self.provider_name(),
                    status=ProviderThreatStatus.MALICIOUS,
                    threat_categories=[threat] + tags,
                    reference_id=urlhaus_id,
                    latency_ms=latency_ms,
                    message=f"Confirmed active malicious URL on URLhaus blacklist: {threat}",
                    raw_details={"url_status": data.get("url_status"), "threat": threat},
                )
            elif query_status == "no_results":
                # STRICT RULE: Absence of report in URLhaus database does NOT prove URL is safe!
                return ThreatCheckResult(
                    provider=self.provider_name(),
                    status=ProviderThreatStatus.UNKNOWN,
                    latency_ms=latency_ms,
                    message="URL not found in URLhaus malware database (threat status indeterminate)",
                )
            else:
                return ThreatCheckResult(
                    provider=self.provider_name(),
                    status=ProviderThreatStatus.UNKNOWN,
                    latency_ms=latency_ms,
                    message=f"URLhaus query status: {query_status}",
                )

        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            logger.warning(f"URLhaus provider lookup failed: {exc}")
            return ThreatCheckResult(
                provider=self.provider_name(),
                status=ProviderThreatStatus.UNAVAILABLE,
                latency_ms=latency_ms,
                message="URLhaus query timed out or network connection unavailable",
            )
        except Exception as exc:
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error(f"Unexpected URLhaus exception: {exc}")
            return ThreatCheckResult(
                provider=self.provider_name(),
                status=ProviderThreatStatus.UNAVAILABLE,
                latency_ms=latency_ms,
                message="Internal exception during URLhaus check",
            )
