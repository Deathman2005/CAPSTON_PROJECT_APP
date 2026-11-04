"""API endpoint for SMS message scanning and multi-signal risk assessment."""

import re
import uuid
import hashlib
from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.scan import ScanRecord
from app.schemas.scan import MessageScanRequest, MessageScanResponse
from app.services.url.normalizer import normalize_and_sanitize_url
from app.services.url.ssrf_protector import validate_url_for_safe_inspection, SSRFViolationError
from app.services.threat_intelligence.aggregator import ThreatAggregator
from app.services.threat_intelligence.base import ProviderThreatStatus
from app.ml.service import SmsClassifierService

router = APIRouter(prefix="/scan", tags=["message-scanner"])
aggregator = ThreatAggregator()
sms_service = SmsClassifierService.get_instance()

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
    description="Inspects SMS text using ML NLP classification, linguistic markers, and embedded malicious links.",
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

    # 1. Machine Learning NLP Text Classification
    ml_result = sms_service.predict(text)

    # 2. Extract and inspect embedded URLs
    urls = request.extracted_urls or extract_urls_from_text(text)
    url_threat_detected = False
    checked_urls = []
    url_reasons = []

    for raw_u in urls[:3]:  # inspect up to 3 links per message
        try:
            norm_info = normalize_and_sanitize_url(raw_u)
            validate_url_for_safe_inspection(norm_info.normalized_url)
            threat_status, _, _, _ = await aggregator.check_url(norm_info.normalized_url)

            if threat_status == ProviderThreatStatus.MALICIOUS:
                url_threat_detected = True
                url_reasons.append(f"Confirmed malicious link identified: {norm_info.hostname}")
            elif threat_status == ProviderThreatStatus.SUSPICIOUS or norm_info.is_ip_address:
                url_reasons.append(f"Suspicious link features detected on domain: {norm_info.hostname}")

            checked_urls.append(norm_info.redacted_url)
        except (ValueError, SSRFViolationError):
            url_reasons.append(f"Suspicious or unroutable link format: {raw_u}")

    # 3. Combine ML Classification and Threat Intelligence
    all_reasons = list(dict.fromkeys(ml_result.reasons + url_reasons))

    classification: str
    risk_score: float
    confidence: float
    recommendation: str

    if url_threat_detected or ml_result.classification == "MALICIOUS":
        classification = "MALICIOUS"
        risk_score = max(ml_result.risk_score, 95.0)
        confidence = max(ml_result.confidence, 0.92)
        recommendation = "HIGH-RISK SCAM: Do not click any links or share information. Banks never demand KYC updates or credentials via SMS links."
    elif ml_result.classification == "SUSPICIOUS" or (urls and len(urls) > 0):
        classification = "SUSPICIOUS"
        risk_score = max(ml_result.risk_score, 65.0)
        confidence = max(ml_result.confidence, 0.80)
        recommendation = "SUSPICIOUS MESSAGE: Exercise caution. Verify directly with your bank or service provider using official customer care channels."
    else:
        classification = "SAFE"
        risk_score = ml_result.risk_score
        confidence = ml_result.confidence
        recommendation = "Message appears authentic. Standard vigilance applies."

    scan_id = uuid.uuid4()

    # 4. Persist Scan Record (STRICT PRIVACY: zero raw SMS text)
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
            sms_model_version=ml_result.model_version,
            message_hash=message_hash,
            detection_reasons="||".join(all_reasons),
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
        reasons=all_reasons,
        extracted_urls=checked_urls,
        recommendation=recommendation,
        model_version=ml_result.model_version,
        timestamp=datetime.now(timezone.utc),
    )
