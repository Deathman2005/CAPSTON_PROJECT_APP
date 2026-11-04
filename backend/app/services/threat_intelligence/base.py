"""Base abstractions and contracts for threat intelligence providers."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ProviderThreatStatus(str, Enum):
    """Normalized provider status classifications."""

    CLEAN = "clean"
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"
    UNCONFIGURED = "unconfigured"


class ThreatCheckResult(BaseModel):
    """Normalized upstream threat intelligence check result."""

    provider: str
    status: ProviderThreatStatus
    threat_categories: List[str] = Field(default_factory=list)
    reference_id: Optional[str] = None
    latency_ms: int = 0
    message: str = ""
    raw_details: Dict[str, Any] = Field(default_factory=dict)


class BaseThreatProvider(ABC):
    """Abstract interface for external threat intelligence integrations."""

    @abstractmethod
    def provider_name(self) -> str:
        """Returns the unique identifier of the provider."""
        pass

    @abstractmethod
    def is_configured(self) -> bool:
        """Checks if required API keys or credentials are present."""
        pass

    @abstractmethod
    async def check_url(self, url: str) -> ThreatCheckResult:
        """
        Queries the upstream threat intelligence service for URL reputation.
        Must enforce timeout caps and never raise unhandled network exceptions.
        """
        pass

