"""Combined Risk Engine: Multi-signal synthesis across NLP, Threat Intelligence, and Lexical ML."""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from app.services.threat_intelligence.base import ProviderThreatStatus


class RiskAssessmentResult(BaseModel):
    """Unified composite risk assessment payload."""

    classification: str = Field(..., description="'SAFE', 'SUSPICIOUS', 'MALICIOUS', or 'UNKNOWN'")
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Calibrated risk score 0.0 to 100.0")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Composite verdict confidence 0.0 to 1.0")
    reasons: List[str] = Field(default_factory=list, description="Aggregated detection reasons and evidence")
    recommendation: str = Field(..., description="Actionable user security guidance")
    component_scores: Dict[str, Optional[float]] = Field(default_factory=dict)
    model_versions: Dict[str, str] = Field(default_factory=dict)


class CombinedRiskEngine:
    """
    Synthesizes multiple decoupled security signals:
    1. SMS Text NLP Scam Probability
    2. Upstream Threat Intelligence Feeds (URLhaus, Google Safe Browsing, VirusTotal)
    3. URL Lexical Machine Learning Features
    4. Domain Deception Heuristics (IP host, shortener, Punycode, TLD)
    """

    @classmethod
    def evaluate(
        cls,
        sms_nlp_score: float = 0.0,
        sms_classification: str = "SAFE",
        sms_confidence: float = 0.90,
        sms_reasons: Optional[List[str]] = None,
        sms_model_version: str = "sms_baseline_v1",
        threat_intel_status: ProviderThreatStatus = ProviderThreatStatus.UNKNOWN,
        threat_intel_score: float = 50.0,
        threat_intel_evidence: Optional[List[str]] = None,
        url_lexical_score: Optional[float] = None,
        url_lexical_confidence: float = 0.85,
        url_lexical_indicators: Optional[List[str]] = None,
        url_model_version: str = "url_baseline_v1",
        has_urls: bool = False,
    ) -> RiskAssessmentResult:
        """Evaluates combined risk based on strict security and evidence standards."""
        sms_reasons = sms_reasons or []
        threat_intel_evidence = threat_intel_evidence or []
        url_lexical_indicators = url_lexical_indicators or []

        all_reasons = list(dict.fromkeys(threat_intel_evidence + sms_reasons + url_lexical_indicators))

        component_scores = {
            "sms_nlp_score": round(sms_nlp_score, 1),
            "threat_intel_score": round(threat_intel_score, 1) if has_urls else None,
            "url_lexical_score": round(url_lexical_score, 1) if url_lexical_score is not None else None,
        }
        model_versions = {
            "sms_model": sms_model_version,
            "url_model": url_model_version,
        }

        # -------------------------------------------------------------------
        # Rule 1: Confirmed Threat Intelligence (Malicious Override)
        # -------------------------------------------------------------------
        if threat_intel_status == ProviderThreatStatus.MALICIOUS:
            return RiskAssessmentResult(
                classification="MALICIOUS",
                risk_score=max(threat_intel_score, 96.0),
                confidence=0.98,
                reasons=all_reasons,
                recommendation="MALICIOUS URL: Threat intelligence confirms active phishing or malware distribution. Do not open link or provide details.",
                component_scores=component_scores,
                model_versions=model_versions,
            )

        # -------------------------------------------------------------------
        # Rule 2: Strong Dual-Signal (SMS Scam + Embedded URL)
        # -------------------------------------------------------------------
        if sms_classification == "MALICIOUS" and has_urls:
            return RiskAssessmentResult(
                classification="MALICIOUS",
                risk_score=max(sms_nlp_score, 92.0),
                confidence=max(sms_confidence, 0.92),
                reasons=all_reasons,
                recommendation="HIGH-RISK SCAM: Urgent phishing lure with embedded link. Legitimate financial institutions never demand KYC updates or credentials via SMS links.",
                component_scores=component_scores,
                model_versions=model_versions,
            )

        # -------------------------------------------------------------------
        # Rule 3: High URL Lexical Risk Score (>= 80.0)
        # -------------------------------------------------------------------
        if url_lexical_score is not None and url_lexical_score >= 80.0:
            if sms_classification in ("MALICIOUS", "SUSPICIOUS"):
                final_cls = "MALICIOUS"
                final_score = max(url_lexical_score, sms_nlp_score, 90.0)
            else:
                final_cls = "SUSPICIOUS"
                final_score = url_lexical_score

            return RiskAssessmentResult(
                classification=final_cls,
                risk_score=final_score,
                confidence=0.88,
                reasons=all_reasons,
                recommendation="DECEPTIVE DESTINATION: Link exhibits structural deception patterns (e.g. raw IP host, Punycode, or deceptive subdomains).",
                component_scores=component_scores,
                model_versions=model_versions,
            )

        # -------------------------------------------------------------------
        # Rule 4: Suspicious Indicators (Threat feed, SMS or Lexical)
        # -------------------------------------------------------------------
        is_suspicious = (
            threat_intel_status == ProviderThreatStatus.SUSPICIOUS
            or sms_classification == "SUSPICIOUS"
            or (url_lexical_score is not None and url_lexical_score >= 60.0)
            or len(url_lexical_indicators) > 0
        )
        if is_suspicious:
            calc_score = max(sms_nlp_score, threat_intel_score if has_urls else 0.0, url_lexical_score or 0.0, 65.0)
            return RiskAssessmentResult(
                classification="SUSPICIOUS",
                risk_score=min(calc_score, 89.0),
                confidence=0.80,
                reasons=all_reasons,
                recommendation="SUSPICIOUS CONTENT: Message or destination exhibits risk indicators. Do not share verification codes or personal information.",
                component_scores=component_scores,
                model_versions=model_versions,
            )

        # -------------------------------------------------------------------
        # Rule 5: Purely SMS Scam without URLs
        # -------------------------------------------------------------------
        if sms_classification == "MALICIOUS":
            return RiskAssessmentResult(
                classification="MALICIOUS",
                risk_score=sms_nlp_score,
                confidence=sms_confidence,
                reasons=all_reasons,
                recommendation="FRAUDULENT MESSAGE: High likelihood of social engineering scam.",
                component_scores=component_scores,
                model_versions=model_versions,
            )

        # -------------------------------------------------------------------
        # Rule 6: Inconclusive / Indeterminate Evidence (UNKNOWN)
        # -------------------------------------------------------------------
        # NON-NEGOTIABLE RULE: When evidence is insufficient or unverified, output UNKNOWN, never SAFE!
        if has_urls and threat_intel_status in (
            ProviderThreatStatus.UNKNOWN,
            ProviderThreatStatus.UNAVAILABLE,
            ProviderThreatStatus.UNCONFIGURED,
        ):
            return RiskAssessmentResult(
                classification="UNKNOWN",
                risk_score=50.0,
                confidence=0.60,
                reasons=all_reasons if all_reasons else ["URL destination has indeterminate reputation"],
                recommendation="UNKNOWN REPUTATION: No threat intelligence reports found, but link destination is unverified. Proceed with caution.",
                component_scores=component_scores,
                model_versions=model_versions,
            )

        # -------------------------------------------------------------------
        # Rule 7: Clean / Safe Consensus
        # -------------------------------------------------------------------
        if has_urls and threat_intel_status == ProviderThreatStatus.CLEAN:
            clean_score = threat_intel_score
            rec = "BENIGN DESTINATION: Link verified clean across configured threat intelligence sources."
        else:
            clean_score = min(sms_nlp_score, 15.0)
            rec = "Message appears authentic. Standard vigilance applies."

        return RiskAssessmentResult(
            classification="SAFE",
            risk_score=clean_score,
            confidence=0.92,
            reasons=all_reasons if all_reasons else ["Content and links verified authentic"],
            recommendation=rec,
            component_scores=component_scores,
            model_versions=model_versions,
        )
