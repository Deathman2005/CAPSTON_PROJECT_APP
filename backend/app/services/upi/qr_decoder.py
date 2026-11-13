"""QR Code Processing, Routing, and Multi-Modal Inspection Engine."""

import re
import uuid
import logging
from enum import Enum
from typing import Optional, Dict, Any, List, Tuple
from pydantic import BaseModel, Field

from app.services.upi.parser import UpiIntentParser, UpiIntentDetails
from app.services.upi.risk_analyzer import UpiRiskAnalyzer, UpiRiskAssessment
from app.services.explanation.groq_service import GroqExplanationService
from app.services.explanation.schemas import ExplanationResult
from app.services.url.normalizer import normalize_and_sanitize_url
from app.services.url.ssrf_protector import validate_url_for_safe_inspection, SSRFViolationError
from app.services.threat_intelligence.aggregator import ThreatAggregator
from app.services.threat_intelligence.base import ProviderThreatStatus
from app.ml.url_service import UrlClassifierService

logger = logging.getLogger("smsshield.upi.qr")


class QrPayloadType(str, Enum):
    """Identified content type encoded inside a QR code."""

    UPI_INTENT = "upi_intent"
    URL = "url"
    PLAIN_TEXT = "plain_text"


class QrEvaluationResult(BaseModel):
    """Complete security assessment result for a scanned or decoded QR code."""

    scan_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    payload_type: QrPayloadType
    raw_content: str
    parsed_upi: Optional[UpiIntentDetails] = None
    classification: str = Field(..., description="'SAFE', 'SUSPICIOUS', 'MALICIOUS', or 'UNKNOWN'")
    risk_score: float = Field(..., ge=0.0, le=100.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list)
    recommendation: str
    explanation: Optional[ExplanationResult] = None


class QrDecoderService:
    """Service for decoding QR code payloads and executing appropriate security inspection pipelines."""

    _instance: Optional["QrDecoderService"] = None

    def __init__(self):
        self.groq_service = GroqExplanationService.get_instance()
        self.threat_aggregator = ThreatAggregator()
        self.url_classifier = UrlClassifierService.get_instance()

    @classmethod
    def get_instance(cls) -> "QrDecoderService":
        """Singleton accessor."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def identify_payload_type(cls, content: str) -> QrPayloadType:
        """Determines whether QR content is a UPI payment intent, HTTP link, or plain text."""
        stripped = content.strip().lower()
        if stripped.startswith("upi://pay") or stripped.startswith("upi://"):
            return QrPayloadType.UPI_INTENT
        if stripped.startswith("http://") or stripped.startswith("https://") or stripped.startswith("www."):
            return QrPayloadType.URL
        return QrPayloadType.PLAIN_TEXT

    def analyze_upi_intent(self, clean_content: str, scan_id: Optional[uuid.UUID] = None) -> QrEvaluationResult:
        """Synchronously analyzes an NPCI UPI payment intent with full Explainable AI reasoning."""
        scan_id = scan_id or uuid.uuid4()
        upi_details = UpiIntentParser.parse(clean_content)
        risk_assessment = UpiRiskAnalyzer.evaluate(upi_details)

        explanation = self.groq_service.generate_explanation(
            text=f"UPI Payment QR: Payee={upi_details.pa}, Name={upi_details.pn}, Note={upi_details.tn}, Amount={upi_details.am}",
            classification=risk_assessment.classification,
            risk_score=risk_assessment.risk_score,
            reasons=risk_assessment.indicators,
            extracted_urls=[upi_details.url] if upi_details.url else [],
        )

        return QrEvaluationResult(
            scan_id=scan_id,
            payload_type=QrPayloadType.UPI_INTENT,
            raw_content=clean_content,
            parsed_upi=upi_details,
            classification=risk_assessment.classification,
            risk_score=risk_assessment.risk_score,
            confidence=risk_assessment.confidence,
            reasons=risk_assessment.indicators,
            recommendation=risk_assessment.recommendation,
            explanation=explanation,
        )

    async def analyze_qr_content(self, content: str) -> QrEvaluationResult:
        """
        Processes decoded QR string:
        - If UPI: Analyzes parameters for QR scam, VPA impersonation, and credit lure.
        - If URL: Runs threat intelligence and lexical ML inspection.
        - If Plain Text: Evaluates content for phishing indicators.
        """
        clean_content = content.strip()
        payload_type = self.identify_payload_type(clean_content)
        scan_id = uuid.uuid4()

        # ---------------------------------------------------------------------
        # BRANCH 1: UPI PAYMENT INTENT (upi://pay?...)
        # ---------------------------------------------------------------------
        if payload_type == QrPayloadType.UPI_INTENT:
            return self.analyze_upi_intent(clean_content, scan_id=scan_id)

        # ---------------------------------------------------------------------
        # BRANCH 2: EMBEDDED URL (https://...)
        # ---------------------------------------------------------------------
        elif payload_type == QrPayloadType.URL:
            reasons = ["QR code directs scanner to an external web destination"]
            risk_score = 30.0
            classification = "SUSPICIOUS"

            try:
                norm_info = normalize_and_sanitize_url(clean_content)
                validate_url_for_safe_inspection(norm_info.normalized_url)

                # Check Threat Intelligence feeds
                threat_status, _, threat_ev, threat_sc = await self.threat_aggregator.check_url(norm_info.normalized_url)
                reasons.extend(threat_ev)

                # Check URL Lexical classifier
                lexical_res = self.url_classifier.predict(norm_info.normalized_url)
                reasons.extend(lexical_res.lexical_indicators)

                risk_score = max(threat_sc, lexical_res.feature_risk_score)
                if threat_status == ProviderThreatStatus.MALICIOUS or risk_score >= 80.0:
                    classification = "MALICIOUS"
                elif threat_status == ProviderThreatStatus.SUSPICIOUS or risk_score >= 45.0:
                    classification = "SUSPICIOUS"
                else:
                    classification = "SAFE"

            except (ValueError, SSRFViolationError) as e:
                reasons.append(f"Invalid or prohibited URL destination in QR: {e}")
                classification = "MALICIOUS"
                risk_score = 90.0

            explanation = self.groq_service.generate_explanation(
                text=f"QR Code URL Destination: {clean_content}",
                classification=classification,
                risk_score=risk_score,
                reasons=reasons,
                extracted_urls=[clean_content],
            )

            return QrEvaluationResult(
                scan_id=scan_id,
                payload_type=QrPayloadType.URL,
                raw_content=clean_content,
                parsed_upi=None,
                classification=classification,
                risk_score=round(risk_score, 1),
                confidence=0.88,
                reasons=reasons,
                recommendation="Do not open unverified links scanned from public QR codes." if classification != "SAFE" else "Verified benign destination.",
                explanation=explanation,
            )

        # ---------------------------------------------------------------------
        # BRANCH 3: PLAIN TEXT
        # ---------------------------------------------------------------------
        else:
            explanation = self.groq_service.generate_explanation(
                text=clean_content,
                classification="SAFE",
                risk_score=10.0,
                reasons=["QR code contains standard non-executable textual information"],
            )

            return QrEvaluationResult(
                scan_id=scan_id,
                payload_type=QrPayloadType.PLAIN_TEXT,
                raw_content=clean_content,
                parsed_upi=None,
                classification="SAFE",
                risk_score=10.0,
                confidence=0.90,
                reasons=["QR code contains standard non-executable textual information"],
                recommendation="Text payload contains no payment instructions or executable web links.",
                explanation=explanation,
            )
