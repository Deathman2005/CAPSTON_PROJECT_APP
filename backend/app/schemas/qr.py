"""Pydantic schemas for QR code security scanning and UPI deep-link analysis."""

import uuid
from datetime import datetime, timezone
from typing import Optional, List
from pydantic import BaseModel, Field

from app.services.upi.parser import UpiIntentDetails
from app.services.explanation.schemas import ExplanationResult


class QrScanRequest(BaseModel):
    """Payload for scanning a decoded QR code string."""

    qr_content: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="The textual payload or URI decoded from the QR code",
        examples=["upi://pay?pa=seller@paytm&pn=SellerName&am=500&cu=INR"],
    )


class QrScanResponse(BaseModel):
    """Comprehensive security assessment response for a scanned QR code."""

    scan_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    payload_type: str = Field(..., description="'upi_intent', 'url', or 'plain_text'")
    raw_content: str
    parsed_upi: Optional[UpiIntentDetails] = Field(
        None,
        description="Structured decomposition if the QR encoded an NPCI UPI payment intent",
    )
    classification: str = Field(..., description="'SAFE', 'SUSPICIOUS', 'MALICIOUS', or 'UNKNOWN'")
    risk_score: float = Field(..., ge=0.0, le=100.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list)
    recommendation: str
    explanation: Optional[ExplanationResult] = Field(
        None,
        description="Explainable AI breakdown with Plain-English reasons, safety actions, and Hindi translation",
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

