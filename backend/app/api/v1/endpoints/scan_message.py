"""API endpoint for SMS message scanning and multi-signal risk assessment."""

import re
import uuid
import hashlib
from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.scan import ScanRecord, UrlScanResult
from app.schemas.scan import MessageScanRequest, MessageScanResponse
from app.services.url.normalizer import normalize_and_sanitize_url
from app.services.url.ssrf_protector import validate_url_for_safe_inspection, SSRFViolationError
from app.services.threat_intelligence.aggregator import ThreatAggregator
from app.services.threat_intelligence.base import ProviderThreatStatus

router = APIRouter(prefix="/scan", tags=["message-scanner"])
aggregator = ThreatAggregator()

# Regex to find embedded URLs in message text
URL_REGEX = re.compile(
    r"\b(?:(?:https?://|www\.)[a-zA-Z0-9.\-_]+(?::\d+)?(?:/[^\s]*)?|(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?)",
    re.IGNORECASE,
)


def extract_urls_from_text(text: str) -> List[str]:
    """Extracts URLs while skipping email addresses."""
    candidates = URL_REGEX.findall(text)
    urls = []
    for c in candidates:
        cleaned = c.strip(".,;:!?)]}\"\'")
        # Skip emails
        if "@" in cleaned or not cleaned:
            continue
        urls.append(cleaned)
    return list(dict.fromkeys(urls))


@router.post(
    "/message",
    response_model=MessageScanResponse,
    summary="Scan and Analyze SMS Message",
    description="Inspects SMS text for social engineering, financial lures, urgency patterns, and embedded malicious links.",
)
async def scan_message(request: MessageScanRequest, db: Session = Depends(get_db)):
    """Evaluate SMS message content and embedded URLs."""
    text = request.message_text.strip()
    if not text:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Message text cannot be empty.",
        )

    # Cryptographic hash of message for duplicate auditing (NEVER store raw text!)
    message_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

    # Discover URLs in message
    urls = request.extracted_urls or extract_urls_from_text(text)

    lower = text.lower()
    reasons: List[str] = []

    # Heuristic Social Engineering and Phishing Markers
    has_urgent_threat = any(k in lower for k in ["blocked", "suspended", "deactivated", "immediate", "within 24 hrs", "penalty"])
    has_kyc = any(k in lower for k in ["kyc", "pan", "aadhaar", "document verification", "update kyc"])
    has_otp_demand = any(k in lower for k in ["otp", "pin", "password", "cvv", "passcode"])
    has_bank_mention = any(k in lower for k in ["sbi", "hdfc", "icici", "axis", "pnb", "bank", "upi", "refund", "lottery"])

    if has_urgent_threat:
        reasons.append("Urgent threat of account deactivation or suspension detected")
    if has_kyc:
        reasons.append("Unverified demand to submit KYC or government identification credentials")
    if has_otp_demand:
        reasons.append("Demand for sensitive verification credentials (OTP/PIN/Password)")
    if has_bank_mention:
        reasons.append("Financial institution or payment provider references detected")

    # Evaluate any embedded URLs against threat intelligence
    url_threat_detected = False
    checked_urls = []

    for raw_u in urls[:3]:  # inspect up to 3 links per message
        try:
            norm_info = normalize_and_sanitize_url(raw_u)
            validate_url_for_safe_inspection(norm_info.normalized_url)
            threat_status, _, _, _ = await aggregator.check_url(norm_info.normalized_url)

            if threat_status == ProviderThreatStatus.MALICIOUS:
                url_threat_detected = True
                reasons.append(f"Confirmed malicious link identified: {norm_info.hostname}")
            elif threat_status == ProviderThreatStatus.SUSPICIOUS or norm_info.is_ip_address:
                reasons.append(f"Suspicious link features detected on domain: {norm_info.hostname}")

            checked_urls.append(norm_info.redacted_url)
        except (ValueError, SSRFViolationError):
            reasons.append(f"Suspicious or unroutable link format: {raw_u}")

    # Risk Synthesis Policy
    classification: str
    risk_score: float
    confidence: float
    recommendation: str

    if url_threat_detected or (urls and (has_urgent_threat or has_kyc or has_otp_demand)):
        classification = "MALICIOUS"
        risk_score = 96.0
        confidence = 0.94
        recommendation = "HIGH-RISK SCAM: Do not click any links or share information. Banks never demand KYC updates or credentials via SMS links."
    elif (has_urgent_threat and has_bank_mention) or (urls and has_bank_mention) or (has_urgent_threat and has_otp_demand):
        classification = "SUSPICIOUS"
        risk_score = 72.0
        confidence = 0.85
        recommendation = "SUSPICIOUS MESSAGE: Exercise caution. Verify directly with your bank using official customer care channels."
    elif urls:
        classification = "SUSPICIOUS"
        risk_score = 60.0
        confidence = 0.75
        recommendation = "Contains unverified external links. Do not open links from unknown senders."
    else:
        classification = "SAFE"
        risk_score = 12.0
        confidence = 0.90
        recommendation = "Message appears authentic. Standard vigilance applies."

    scan_id = uuid.uuid4()

    # Persist Scan Record (STRICT PRIVACY: zero raw SMS text)
    try:
        record = ScanRecord(
            id=scan_id,
            timestamp=datetime.now(timezone.utc),
            source_category=request.source_type,
            source_package=request.source_package,
            classification=classification,
            risk_score=risk_score,
            confidence=confidence,
            url_count=len(urls),
            sms_model_version="sms_v1_heuristic_20261105",
            message_hash=message_hash,
            detection_reasons="||".join(reasons),
            recommendation=recommendation,
        )
        db.add(record)
        db.commit()
    except Exception:
        db.rollback()

    return MessageScanResponse(
        scan_id=scan_id,
        classification=classification,
        confidence=confidence,
        risk_score=risk_score,
        reasons=reasons,
        extracted_urls=checked_urls,
        recommendation=recommendation,
        model_version="sms_v1_heuristic_20261105",
        timestamp=datetime.now(timezone.utc),
    )
