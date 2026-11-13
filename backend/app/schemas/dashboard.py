"""Pydantic schemas for Dashboard analytics and monitoring endpoints."""

import uuid
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class DashboardStatsResponse(BaseModel):
    """Aggregate statistics for the security dashboard."""
    total_scans: int = 0
    safe_scans: int = 0
    suspicious_scans: int = 0
    malicious_scans: int = 0
    unknown_scans: int = 0
    total_urls_scanned: int = 0
    avg_risk_score: float = 0.0
    timestamp: datetime


class RecentScanItem(BaseModel):
    """Minimal audit record for recent scans (zero raw SMS text)."""
    scan_id: uuid.UUID
    timestamp: datetime
    source_category: str
    source_package: Optional[str] = None
    classification: str
    risk_score: Optional[float] = None
    confidence: float
    url_count: int
    detection_reasons: List[str] = Field(default_factory=list)
    recommendation: Optional[str] = None


class RecentScansResponse(BaseModel):
    """List of recent audit scan records."""
    total_returned: int
    items: List[RecentScanItem]


class ThreatDistributionCategory(BaseModel):
    name: str
    count: int
    percentage: float


class ThreatDistributionResponse(BaseModel):
    """Breakdown of classifications and source categories for charting."""
    classifications: List[ThreatDistributionCategory]
    sources: List[ThreatDistributionCategory]
    timestamp: datetime

