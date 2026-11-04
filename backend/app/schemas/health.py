"""Pydantic schemas for health and system diagnostic endpoints."""

from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field


class DatabaseHealth(BaseModel):
    """Database connectivity status schema."""

    status: str = Field(..., description="Connection status: connected, disconnected, unhealthy")
    dialect: str = Field(..., description="Database dialect, e.g. postgresql, sqlite")
    latency_ms: Optional[float] = Field(None, description="Roundtrip query latency in milliseconds")
    error: Optional[str] = Field(None, description="Error message if check failed")


class ProviderHealthItem(BaseModel):
    """Threat intelligence provider status item."""

    name: str = Field(..., description="Provider name, e.g. google_safe_browsing, urlhaus")
    status: str = Field(..., description="Operational status: available, unconfigured, unavailable")
    latency_ms: Optional[float] = Field(None, description="Check latency if performed")
    message: str = Field(..., description="Human-readable status summary")


class ProvidersHealthResponse(BaseModel):
    """Response schema for threat intelligence provider status check."""

    providers: List[ProviderHealthItem]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class HealthResponse(BaseModel):
    """Root health verification response schema."""

    status: str = Field(..., description="Overall service status: healthy, degraded, unhealthy")
    app_name: str
    version: str
    environment: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    database: DatabaseHealth
