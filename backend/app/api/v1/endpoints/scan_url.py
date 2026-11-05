"""API endpoint for single URL security inspection and threat intelligence analysis."""

import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.scan import UrlScanResult, ThreatProviderResult
from app.schemas.scan import UrlScanRequest, UrlScanResponse, ProviderResultSchema
from app.services.url.normalizer import normalize_and_sanitize_url
from app.services.url.ssrf_protector import validate_url_for_safe_inspection, SSRFViolationError
from app.services.threat_intelligence.aggregator import ThreatAggregator
from app.services.threat_intelligence.base import ProviderThreatStatus
from app.ml.url_service import UrlClassifierService
from app.services.risk_engine.engine import CombinedRiskEngine

router = APIRouter(prefix="/scan", tags=["url-scanner"])
aggregator = ThreatAggregator()
url_service = UrlClassifierService.get_instance()


@router.post(
    "/url",
    response_model=UrlScanResponse,
    summary="Scan and Analyze URL",
    description="Normalizes URL, verifies SSRF safety, queries threat intelligence feeds, evaluates lexical ML features, and synthesizes combined risk.",
)
async def scan_url(request: UrlScanRequest, db: Session = Depends(get_db)):
    """Evaluate target URL for phishing, malware, and social engineering threats."""
    raw_url = request.url.strip()

    # 1. Normalization & Sanitization
    try:
        norm_info = normalize_and_sanitize_url(raw_url)
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Malformed URL: {str(ve)}",
        )

    # 2. SSRF Protection Gate
    try:
        validate_url_for_safe_inspection(norm_info.normalized_url)
    except SSRFViolationError as se:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"SSRF Violation: {str(se)}",
        )

    # 3. Query Threat Intelligence Feeds
    overall_threat, provider_results, threat_evidence, threat_score = await aggregator.check_url(norm_info.normalized_url)

    # 4. Lexical Machine Learning Evaluation
    lexical_result = url_service.predict(norm_info.normalized_url)

    # 5. Combined Multi-Signal Risk Engine
    risk_assessment = CombinedRiskEngine.evaluate(
        sms_nlp_score=0.0,
        sms_classification="SAFE",
        threat_intel_status=overall_threat,
        threat_intel_score=threat_score,
        threat_intel_evidence=threat_evidence,
        url_lexical_score=lexical_result.feature_risk_score,
        url_lexical_confidence=lexical_result.confidence,
        url_lexical_indicators=lexical_result.lexical_indicators,
        url_model_version=lexical_result.model_version,
        has_urls=True,
    )

    # Map engine classification to URL response schema format
    cls_map = {
        "SAFE": "benign",
        "SUSPICIOUS": "suspicious",
        "MALICIOUS": "malicious",
        "UNKNOWN": "unknown",
    }
    final_classification = cls_map.get(risk_assessment.classification, "unknown")
    final_risk_score = risk_assessment.risk_score

    scan_id = uuid.uuid4()

    # 6. Persist to Database (Redacted URL only, zero sensitive tokens)
    try:
        url_record = UrlScanResult(
            id=scan_id,
            normalized_url=norm_info.redacted_url,
            domain=norm_info.hostname,
            is_ip_address=norm_info.is_ip_address,
            is_shortened=norm_info.is_shortened,
            is_punycode=norm_info.is_punycode,
            classification=final_classification,
            feature_risk_score=final_risk_score,
            reputation_status=overall_threat.value,
        )
        db.add(url_record)

        for p_name, p_res in provider_results.items():
            prov_rec = ThreatProviderResult(
                id=uuid.uuid4(),
                url_scan_id=scan_id,
                provider_name=p_name,
                status=p_res.status.value,
                latency_ms=p_res.latency_ms,
                threat_tags=",".join(p_res.threat_categories) if p_res.threat_categories else None,
                reference_id=p_res.reference_id,
            )
            db.add(prov_rec)

        db.commit()
    except Exception:
        db.rollback()

    # Format response
    providers_schema_map = {
        name: ProviderResultSchema(
            provider=r.provider,
            status=r.status.value,
            threat_categories=r.threat_categories,
            reference_id=r.reference_id,
            latency_ms=r.latency_ms,
            message=r.message,
        )
        for name, r in provider_results.items()
    }

    return UrlScanResponse(
        scan_id=scan_id,
        original_url=raw_url,
        normalized_url=norm_info.redacted_url,
        hostname=norm_info.hostname,
        is_ip_address=norm_info.is_ip_address,
        is_shortened=norm_info.is_shortened,
        is_punycode=norm_info.is_punycode,
        threat_intelligence_results=providers_schema_map,
        final_url_classification=final_classification,
        risk_score=final_risk_score,
        evidence=risk_assessment.reasons,
        recommendation=risk_assessment.recommendation,
        timestamp=datetime.now(timezone.utc),
    )
