"""Unit tests for the Combined Risk Engine and multi-signal synthesis policies."""

import pytest
from app.services.threat_intelligence.base import ProviderThreatStatus
from app.services.risk_engine.engine import CombinedRiskEngine, RiskAssessmentResult


def test_malicious_threat_intelligence_override():
    """Verify upstream MALICIOUS threat intelligence overrides other signals."""
    res = CombinedRiskEngine.evaluate(
        sms_nlp_score=10.0,
        sms_classification="SAFE",
        threat_intel_status=ProviderThreatStatus.MALICIOUS,
        threat_intel_score=98.0,
        threat_intel_evidence=["Confirmed active malware on URLhaus"],
        has_urls=True,
    )
    assert res.classification == "MALICIOUS"
    assert res.risk_score >= 95.0
    assert res.confidence >= 0.95
    assert "Threat intelligence" in res.recommendation


def test_dual_signal_sms_scam_with_embedded_link():
    """Verify SMS phishing with an embedded link triggers MALICIOUS even if threat intel is UNKNOWN."""
    res = CombinedRiskEngine.evaluate(
        sms_nlp_score=95.0,
        sms_classification="MALICIOUS",
        sms_reasons=["Urgent KYC verification demand"],
        threat_intel_status=ProviderThreatStatus.UNKNOWN,
        threat_intel_score=50.0,
        url_lexical_score=55.0,
        has_urls=True,
    )
    assert res.classification == "MALICIOUS"
    assert res.risk_score >= 90.0
    assert "HIGH-RISK SCAM" in res.recommendation


def test_high_url_lexical_risk():
    """Verify high lexical score (e.g. raw IP host or Punycode) elevates classification."""
    res = CombinedRiskEngine.evaluate(
        sms_nlp_score=20.0,
        sms_classification="SAFE",
        threat_intel_status=ProviderThreatStatus.UNKNOWN,
        threat_intel_score=50.0,
        url_lexical_score=85.0,
        url_lexical_indicators=["Destination is a raw IP address"],
        has_urls=True,
    )
    assert res.classification in ("MALICIOUS", "SUSPICIOUS")
    assert res.risk_score >= 80.0


def test_indeterminate_unknown_reputation():
    """NON-NEGOTIABLE RULE: When evidence is unverified/unknown, return UNKNOWN, not SAFE."""
    res = CombinedRiskEngine.evaluate(
        sms_nlp_score=25.0,
        sms_classification="SAFE",
        threat_intel_status=ProviderThreatStatus.UNKNOWN,
        threat_intel_score=50.0,
        url_lexical_score=30.0,
        has_urls=True,
    )
    assert res.classification == "UNKNOWN"
    assert res.risk_score == 50.0
    assert "UNKNOWN REPUTATION" in res.recommendation


def test_safe_clean_consensus():
    """Verify message without links or with verified clean link is marked SAFE."""
    # Scenario A: Message without links
    res_no_link = CombinedRiskEngine.evaluate(
        sms_nlp_score=10.0,
        sms_classification="SAFE",
        has_urls=False,
    )
    assert res_no_link.classification == "SAFE"
    assert res_no_link.risk_score <= 15.0

    # Scenario B: Message with verified clean link
    res_clean_link = CombinedRiskEngine.evaluate(
        sms_nlp_score=8.0,
        sms_classification="SAFE",
        threat_intel_status=ProviderThreatStatus.CLEAN,
        threat_intel_score=10.0,
        url_lexical_score=15.0,
        has_urls=True,
    )
    assert res_clean_link.classification == "SAFE"
    assert res_clean_link.risk_score <= 15.0
