"""API endpoint for SMS message scanning and multi-signal risk assessment."""

import re
import uuid
import hashlib
from datetime import datetime, timezone
from typing import List, Optional
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
from app.ml.url_service import UrlClassifierService
from app.services.risk_engine.engine import CombinedRiskEngine
from app.services.explanation.groq_service import GroqExplanationService

router = APIRouter(prefix="/scan", tags=["message-scanner"])
aggregator = ThreatAggregator()
sms_service = SmsClassifierService.get_instance()
url_service = UrlClassifierService.get_instance()
groq_service = GroqExplanationService.get_instance()

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
    description="Inspects SMS text using ML NLP classification, threat intelligence, URL lexical ML, and combined risk engine.",
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
    checked_urls = []
    threat_intel_evidence = []
    url_lexical_indicators = []
    worst_threat_status = ProviderThreatStatus.CLEAN if urls else ProviderThreatStatus.UNKNOWN
    max_threat_score = 0.0
    max_lexical_score: Optional[float] = None
    url_version = "url_baseline_v1"

    for raw_u in urls[:3]:  # inspect up to 3 links per message
        try:
            norm_info = normalize_and_sanitize_url(raw_u)
            validate_url_for_safe_inspection(norm_info.normalized_url)

            # Upstream Threat Intelligence Feeds
            threat_status, _, threat_ev, threat_sc = await aggregator.check_url(norm_info.normalized_url)
            threat_intel_evidence.extend(threat_ev)
            if threat_status == ProviderThreatStatus.MALICIOUS:
                worst_threat_status = ProviderThreatStatus.MALICIOUS
                max_threat_score = max(max_threat_score, threat_sc)
            elif threat_status == ProviderThreatStatus.SUSPICIOUS and worst_threat_status != ProviderThreatStatus.MALICIOUS:
                worst_threat_status = ProviderThreatStatus.SUSPICIOUS
                max_threat_score = max(max_threat_score, threat_sc)
            elif worst_threat_status not in (ProviderThreatStatus.MALICIOUS, ProviderThreatStatus.SUSPICIOUS):
                worst_threat_status = threat_status
                max_threat_score = max(max_threat_score, threat_sc)

            # URL Lexical Machine Learning Classifier
            lexical_res = url_service.predict(norm_info.normalized_url)
            url_lexical_indicators.extend(lexical_res.lexical_indicators)
            url_version = lexical_res.model_version
            if max_lexical_score is None or lexical_res.feature_risk_score > max_lexical_score:
                max_lexical_score = lexical_res.feature_risk_score

            checked_urls.append(norm_info.redacted_url)
        except (ValueError, SSRFViolationError) as err:
            url_lexical_indicators.append(f"Suspicious or unroutable link format: {raw_u}")
            worst_threat_status = ProviderThreatStatus.SUSPICIOUS
            max_threat_score = max(max_threat_score, 70.0)

    # 3. Combined Multi-Signal Risk Engine
    risk_assessment = CombinedRiskEngine.evaluate(
        sms_nlp_score=ml_result.risk_score,
        sms_classification=ml_result.classification,
        sms_confidence=ml_result.confidence,
        sms_reasons=ml_result.reasons,
        sms_model_version=ml_result.model_version,
        threat_intel_status=worst_threat_status,
        threat_intel_score=max_threat_score,
        threat_intel_evidence=threat_intel_evidence,
        url_lexical_score=max_lexical_score,
        url_lexical_confidence=0.85,
        url_lexical_indicators=url_lexical_indicators,
        url_model_version=url_version,
        has_urls=len(urls) > 0,
    )

    # 4. Explainable AI (XAI) Synthesis via Groq with Deterministic Local Fallback
    explanation = groq_service.generate_explanation(
        text=text,
        classification=risk_assessment.classification,
        risk_score=risk_assessment.risk_score,
        reasons=risk_assessment.reasons,
        extracted_urls=checked_urls,
        token_attributions=ml_result.token_attributions,
        top_risk_tokens=ml_result.top_risk_tokens,
        top_safe_tokens=ml_result.top_safe_tokens,
    )

    scan_id = uuid.uuid4()

    # 5. Persist Scan Record (STRICT PRIVACY: zero raw SMS text)
    try:
        record = ScanRecord(
            id=scan_id,
            timestamp=datetime.now(timezone.utc),
            source_category=request.source_type,
            source_package=request.source_package,
            classification=risk_assessment.classification,
            risk_score=risk_assessment.risk_score,
            confidence=risk_assessment.confidence,
            url_count=len(urls),
            sms_model_version=f"{ml_result.model_version}|{url_version}",
            message_hash=message_hash,
            detection_reasons="||".join(risk_assessment.reasons),
            recommendation=risk_assessment.recommendation,
        )
        db.add(record)
        db.commit()
    except Exception:
        db.rollback()

    return MessageScanResponse(
        scan_id=scan_id,
        classification=risk_assessment.classification,
        confidence=risk_assessment.confidence,
        risk_score=risk_assessment.risk_score,
        reasons=risk_assessment.reasons,
        extracted_urls=checked_urls,
        recommendation=risk_assessment.recommendation,
        model_version=f"{ml_result.model_version}|{url_version}",
        explanation=explanation,
        timestamp=datetime.now(timezone.utc),
    )
