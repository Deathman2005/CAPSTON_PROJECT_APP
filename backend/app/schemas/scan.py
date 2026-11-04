"""Pydantic schemas for URL and SMS message scanning endpoints."""

import uuid
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class UrlScanRequest(BaseModel):
    """Payload for scanning an individual URL."""

    url: str = Field(
        ...,
        min_length=3,
        max_length=2048,
        description="The target URL or domain to evaluate.",
        examples=["http://sbi-kyc-verification.xyz/login"],
    )


class ProviderResultSchema(BaseModel):
    """Structured report from an individual threat intelligence provider."""

    provider: str
    status: str
    threat_categories: List[str] = Field(default_factory=list)
    reference_id: Optional[str] = None
    latency_ms: int = 0
    message: str = ""


class UrlScanResponse(BaseModel):
    """Complete URL threat intelligence and lexical analysis report."""

    scan_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    original_url: str
    normalized_url: str
    hostname: str
    is_ip_address: bool
    is_shortened: bool
    is_punycode: bool
    threat_intelligence_results: Dict[str, ProviderResultSchema]
    final_url_classification: str = Field(
        ...,
        description="'benign', 'phishing', 'malware', 'suspicious', 'unknown'",
    )
    risk_score: float = Field(..., ge=0.0, le=100.0)
    evidence: List[str] = Field(default_factory=list)
    recommendation: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class MessageScanRequest(BaseModel):
    """Payload for scanning SMS message text."""

    message_text: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Visible SMS message content for analysis.",
    )
    source_type: str = Field(
        default="manual_input",
        description="'manual_input', 'manual_share', or 'notification_auto'",
    )
    source_package: Optional[str] = Field(
        None,
        description="Source application package name if available.",
    )
    extracted_urls: List[str] = Field(
        default_factory=list,
        description="Optional list of client-extracted URLs.",
    )
    consent_metadata: Optional[Dict[str, Any]] = None


class MessageScanResponse(BaseModel):
    """Analysis result for an SMS message."""

    scan_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    classification: str = Field(..., description="'SAFE', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN'")
    confidence: float = Field(..., ge=0.0, le=1.0)
    risk_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    reasons: List[str] = Field(default_factory=list)
    extracted_urls: List[str] = Field(default_factory=list)
    recommendation: str
    model_version: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
