"""VirusTotal API v3 Threat Intelligence Adapter."""

import time
import base64
import logging
import httpx
from app.core.config import settings
from app.services.threat_intelligence.base import (
    BaseThreatProvider,
    ThreatCheckResult,
    ProviderThreatStatus,
)

logger = logging.getLogger("smsshield.threat.virustotal")


class VirusTotalProvider(BaseThreatProvider):
    """
    Adapter for VirusTotal API v3 URL report analysis.
    Aggregates multi-engine security scanner results.
    """

    API_URL = "https://www.virustotal.com/api/v3/urls"
    TIMEOUT_SECONDS = 3.0

    def provider_name(self) -> str:
        return "virustotal"

    def is_configured(self) -> bool:
        return bool(settings.VIRUSTOTAL_API_KEY and settings.VIRUSTOTAL_API_KEY.strip())

    async def check_url(self, url: str) -> ThreatCheckResult:
        if not self.is_configured():
            return ThreatCheckResult(
                provider=self.provider_name(),
                status=ProviderThreatStatus.UNCONFIGURED,
                message="VirusTotal API key not configured in environment (optional provider)",
            )

        start_time = time.perf_counter()
        # VT uses URL identifier: base64 without padding
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")

        headers = {
            "x-apikey": settings.VIRUSTOTAL_API_KEY,
            "User-Agent": "SMSShield-SecurityBot/1.0",
        }

        try:
            async with httpx.AsyncClient(timeout=self.TIMEOUT_SECONDS) as client:
                response = await client.get(
                    f"{self.API_URL}/{url_id}",
                    headers=headers,
                )

            latency_ms = int((time.perf_counter() - start_time) * 1000)

            if response.status_code == 404:
                return ThreatCheckResult(
                    provider=self.provider_name(),
                    status=ProviderThreatStatus.UNKNOWN,
                    latency_ms=latency_ms,
                    message="URL has not yet been analyzed by VirusTotal community",
                )

            if response.status_code != 200:
                logger.warning(f"VirusTotal API returned HTTP {response.status_code}")
                return ThreatCheckResult(
                    provider=self.provider_name(),
                    status=ProviderThreatStatus.UNAVAILABLE,
                    latency_ms=latency_ms,
                    message=f"VirusTotal API returned HTTP {response.status_code}",
                )

            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)

            categories = []
            if malicious >= 2:
                categories.append(f"flagged_by_{malicious}_antivirus_engines")
                return ThreatCheckResult(
                    provider=self.provider_name(),
                    status=ProviderThreatStatus.MALICIOUS,
                    threat_categories=categories,
                    reference_id=url_id,
                    latency_ms=latency_ms,
                    message=f"VirusTotal flagged URL as malicious by {malicious} security vendors",
                    raw_details={"stats": stats},
                )
            elif malicious == 1 or suspicious >= 2:
                categories.append(f"suspicious_indicators_{suspicious}")
                return ThreatCheckResult(
                    provider=self.provider_name(),
                    status=ProviderThreatStatus.SUSPICIOUS,
                    threat_categories=categories,
                    reference_id=url_id,
                    latency_ms=latency_ms,
                    message=f"VirusTotal reported suspicious indicators (suspicious={suspicious}, malicious={malicious})",
                    raw_details={"stats": stats},
                )
            elif harmless > 0:
                return ThreatCheckResult(
                    provider=self.provider_name(),
                    status=ProviderThreatStatus.CLEAN,
                    reference_id=url_id,
                    latency_ms=latency_ms,
                    message=f"VirusTotal community analysis clean (harmless={harmless}, malicious=0)",
                    raw_details={"stats": stats},
                )
            else:
                return ThreatCheckResult(
                    provider=self.provider_name(),
                    status=ProviderThreatStatus.UNKNOWN,
                    latency_ms=latency_ms,
                    message="Insufficient analysis telemetry on VirusTotal",
                    raw_details={"stats": stats},
                )

        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            logger.warning(f"VirusTotal query failed: {exc}")
            return ThreatCheckResult(
                provider=self.provider_name(),
                status=ProviderThreatStatus.UNAVAILABLE,
                latency_ms=latency_ms,
                message="VirusTotal query timed out or unreachable",
            )
        except Exception as exc:
            latency_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error(f"Unexpected VirusTotal exception: {exc}")
            return ThreatCheckResult(
                provider=self.provider_name(),
                status=ProviderThreatStatus.UNAVAILABLE,
                latency_ms=latency_ms,
                message="Internal exception during VirusTotal check",
            )
