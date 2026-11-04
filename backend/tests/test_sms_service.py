"""Unit tests for the production SMS inference service and fallback resilience."""

import pytest
from app.ml.service import SmsClassifierService, SmsClassificationResult


@pytest.fixture
def service():
    return SmsClassifierService.get_instance()


def test_predict_phishing_message(service: SmsClassifierService):
    """Verify phishing SMS triggers MALICIOUS or high SUSPICIOUS classification."""
    msg = (
        "Dear SBI Customer, your Netbanking access is suspended due to pending KYC. "
        "Update immediately at https://sbi-kyc-verify.net"
    )
    result = service.predict(msg)
    assert isinstance(result, SmsClassificationResult)
    assert result.classification in ("MALICIOUS", "SUSPICIOUS")
    assert result.risk_score >= 50.0
    assert len(result.reasons) > 0
    assert any("kyc" in r.lower() or "urgency" in r.lower() for r in result.reasons)


def test_predict_conversational_clean_message(service: SmsClassifierService):
    """Verify regular personal conversation is classified as SAFE."""
    msg = "Hi Dad, what time are we having dinner tonight? See you soon."
    result = service.predict(msg)
    assert isinstance(result, SmsClassificationResult)
    assert result.classification == "SAFE"
    assert result.risk_score <= 40.0


def test_predict_electricity_bill_scare(service: SmsClassifierService):
    """Verify utility disconnection threat is detected."""
    msg = "Dear consumer your electricity power will be disconnected tonight at 9:30 PM due to unpaid bill. Call 9876543210."
    result = service.predict(msg)
    assert result.classification in ("MALICIOUS", "SUSPICIOUS")
    assert any("electricity" in r.lower() or "disconnection" in r.lower() for r in result.reasons)


def test_predict_benign_transactional_otp(service: SmsClassifierService):
    """Verify authentic benign OTP message with no threats or URLs is classified safely."""
    msg = "492018 is your Swiggy login code. Do not share this OTP with anyone."
    result = service.predict(msg)
    assert result.classification == "SAFE"
    assert result.risk_score <= 45.0


def test_heuristic_fallback_resilience():
    """Verify service gracefully falls back when ML pipeline artifact is absent."""
    service = SmsClassifierService(model_path="non_existent_file.joblib", metrics_path="non_existent.json")
    assert service.pipeline is None

    result = service.predict("Urgent: Account blocked. Update KYC at http://phish.com")
    assert result.is_fallback is True
    assert result.classification == "MALICIOUS"
    assert result.risk_score >= 90.0
