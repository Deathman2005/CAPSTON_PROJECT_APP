"""Threat intelligence provider aggregator and multi-source consensus engine."""

import asyncio
import logging
from typing import List, Dict, Tuple
from app.services.threat_intelligence.base import (
    BaseThreatProvider,
    ThreatCheckResult,
    ProviderThreatStatus,
)
from app.services.threat_intelligence.urlhaus import URLhausProvider
from app.services.threat_intelligence.google_safe_browsing import GoogleSafeBrowsingProvider
from app.services.threat_intelligence.virustotal import VirusTotalProvider

logger = logging.getLogger("smsshield.threat.aggregator")


class ThreatAggregator:
    """
    Coordinates upstream threat intelligence checks across multiple providers concurrently,
    aggregates provider results, and determines overall reputation verdict according to strict
    evidence standards.
    """

    def __init__(self, providers: List[BaseThreatProvider] | None = None):
        self.providers = providers or [
            URLhausProvider(),
            GoogleSafeBrowsingProvider(),
            VirusTotalProvider(),
        ]

    async def check_url(self, url: str) -> Tuple[ProviderThreatStatus, Dict[str, ThreatCheckResult], List[str], float]:
        """
        Queries all providers in parallel, calculates composite reputation status,
        evidence reasons, and normalized reputation score (0.0 to 100.0).
        """
        tasks = [provider.check_url(url) for provider in self.providers]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        results_map: Dict[str, ThreatCheckResult] = {}
        evidence: List[str] = []

        for provider, res in zip(self.providers, results_list):
            name = provider.provider_name()
            if isinstance(res, Exception):
                logger.error(f"Provider {name} raised unexpected error: {res}")
                results_map[name] = ThreatCheckResult(
                    provider=name,
                    status=ProviderThreatStatus.UNAVAILABLE,
                    message=f"Check failed: {str(res)}",
                )
            elif isinstance(res, ThreatCheckResult):
                results_map[name] = res
            else:
                results_map[name] = ThreatCheckResult(
                    provider=name,
                    status=ProviderThreatStatus.UNAVAILABLE,
                    message="Invalid result returned",
                )

        # Consensus Evaluation
        has_malicious = any(r.status == ProviderThreatStatus.MALICIOUS for r in results_map.values())
        has_suspicious = any(r.status == ProviderThreatStatus.SUSPICIOUS for r in results_map.values())
        has_clean = any(r.status == ProviderThreatStatus.CLEAN for r in results_map.values())
        all_unknown_or_unavailable = all(
            r.status in (ProviderThreatStatus.UNKNOWN, ProviderThreatStatus.UNAVAILABLE, ProviderThreatStatus.UNCONFIGURED)
            for r in results_map.values()
        )

        overall_status: ProviderThreatStatus
        reputation_score: float

        if has_malicious:
            overall_status = ProviderThreatStatus.MALICIOUS
            reputation_score = 98.0
            for name, r in results_map.items():
                if r.status == ProviderThreatStatus.MALICIOUS:
                    evidence.append(f"Confirmed malicious by {name.replace('_', ' ').title()}: {r.message}")
        elif has_suspicious:
            overall_status = ProviderThreatStatus.SUSPICIOUS
            reputation_score = 65.0
            for name, r in results_map.items():
                if r.status == ProviderThreatStatus.SUSPICIOUS:
                    evidence.append(f"Flagged suspicious by {name.replace('_', ' ').title()}: {r.message}")
        elif all_unknown_or_unavailable:
            # NON-NEGOTIABLE RULE: When no positive or negative reports exist, status is UNKNOWN
            overall_status = ProviderThreatStatus.UNKNOWN
            reputation_score = 50.0
            evidence.append("No definitive threat intelligence match found across upstream providers (status indeterminate)")
        elif has_clean:
            overall_status = ProviderThreatStatus.CLEAN
            reputation_score = 10.0
            evidence.append("URL verified clean across configured threat intelligence sources")
        else:
            overall_status = ProviderThreatStatus.UNKNOWN
            reputation_score = 50.0

        return overall_status, results_map, evidence, reputation_score
