"""Unit tests for Token Attribution and TreeSHAP Explainable AI (XAI) Engine."""

from pathlib import Path
import pytest
import joblib
from app.ml.attribution import TokenAttributionEngine, TokenSpan, AttributionExplanation
from app.ml.preprocessor import SmsPreprocessor
from app.ml.service import SmsClassifierService
from app.services.explanation.groq_service import GroqExplanationService

ARTIFACT_PATH = Path(__file__).parent.parent / "app" / "ml" / "artifacts" / "sms_classifier.joblib"


@pytest.fixture
def trained_pipeline():
    """Loads the trained model pipeline from artifacts."""
    return joblib.load(ARTIFACT_PATH)


def test_token_attribution_on_known_scam(trained_pipeline):
    """Verify that scam keywords (blocked, kyc, immediately) are identified with positive risk weights."""
    raw_text = "Dear customer, your SBI account will be blocked today. Update your KYC immediately."
    preprocessor = SmsPreprocessor(mask_entities=True)
    cleaned_text = preprocessor.clean_and_normalize(raw_text)

    attribution = TokenAttributionEngine.explain(trained_pipeline, raw_text, cleaned_text)

    assert isinstance(attribution, AttributionExplanation)
    assert len(attribution.tokens) > 0
    assert len(attribution.top_risk_tokens) > 0

    # Ensure character offsets exactly match the original string substring
    for span in attribution.tokens:
        assert raw_text[span.start:span.end] == span.token

    # Verify that core scam drivers receive 'risk' classification
    risk_tokens = [s.token.lower() for s in attribution.tokens if s.impact == "risk"]
    assert any(k in risk_tokens for k in ["blocked", "kyc", "immediately"])


def test_token_attribution_on_safe_transaction(trained_pipeline):
    """Verify that legitimate transactional messages produce safe anchors or neutral tokens."""
    raw_text = "Rs. 1,450.00 debited from A/C XX4921 at SWIGGY BANGALORE. Avl Bal: Rs. 48,210.50."
    preprocessor = SmsPreprocessor(mask_entities=True)
    cleaned_text = preprocessor.clean_and_normalize(raw_text)

    attribution = TokenAttributionEngine.explain(trained_pipeline, raw_text, cleaned_text)

    assert isinstance(attribution, AttributionExplanation)
    # Check that character offsets are valid
    for span in attribution.tokens:
        assert raw_text[span.start:span.end] == span.token


def test_heuristic_attribution_fallback():
    """Verify heuristic attribution functions when pipeline is None."""
    raw_text = "Urgent: Your electricity power cut tonight at 9:30 PM. Pay bill now."
    preprocessor = SmsPreprocessor(mask_entities=True)
    cleaned_text = preprocessor.clean_and_normalize(raw_text)

    attribution = TokenAttributionEngine.explain(None, raw_text, cleaned_text)

    assert attribution.attribution_method == "Heuristic Linguistic Attribution"
    assert len(attribution.tokens) > 0
    for span in attribution.tokens:
        assert raw_text[span.start:span.end] == span.token

    risk_words = [s.token.lower() for s in attribution.tokens if s.impact == "risk"]
    assert any(w in risk_words for w in ["urgent", "power cut", "tonight", "pay"])


def test_sms_classifier_service_integration():
    """Verify SmsClassifierService returns token_attributions and top_risk_tokens."""
    service = SmsClassifierService.get_instance()
    res = service.predict("Your HDFC debit card has been suspended. Call customer care immediately.")

    assert res.classification in ("MALICIOUS", "SUSPICIOUS")
    assert res.risk_score >= 60.0
    assert len(res.token_attributions) > 0
    assert len(res.top_risk_tokens) > 0

    for span in res.token_attributions:
        assert isinstance(span, TokenSpan)
        assert span.start >= 0
        assert span.end > span.start


def test_groq_service_propagates_token_attributions():
    """Verify GroqExplanationService propagates token attributions into final ExplanationResult."""
    scam_msg = "Dear consumer, your electricity power will be disconnected tonight at 9:30 PM from electric office. Call electricity officer immediately: 9876501234."
    service = SmsClassifierService.get_instance()
    ml_result = service.predict(scam_msg)

    groq_service = GroqExplanationService(api_key="")
    explanation = groq_service.generate_explanation(
        text=scam_msg,
        classification=ml_result.classification,
        risk_score=ml_result.risk_score,
        reasons=ml_result.reasons,
        token_attributions=ml_result.token_attributions,
        top_risk_tokens=ml_result.top_risk_tokens,
        top_safe_tokens=ml_result.top_safe_tokens,
    )

    assert len(explanation.token_attributions) > 0
    assert len(explanation.top_risk_tokens) > 0
    assert explanation.fraud_type == "electricity_disconnection_scam"
