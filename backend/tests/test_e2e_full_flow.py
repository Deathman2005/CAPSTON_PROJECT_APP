"""End-to-End Integration Suite for Phase 6.

Validates the complete pipeline across all 12 Indian financial fraud archetypes,
clean transactional messages, and UPI QR intent scenarios.
"""

import pytest

from app.ml.service import SmsClassifierService
from app.services.explanation.groq_service import GroqExplanationService
from app.services.upi.qr_decoder import QrDecoderService


ALL_12_FRAUD_SAMPLES = [
    (
        "fake_payment_confirmation",
        "Payment Successful: You received Rs 12,500 on PhonePe from buyer. Settle payment at http://phonepe-verify.link",
        "fake_payment_confirmation",
    ),
    (
        "fake_upi_collect_request",
        "Approve UPI collect request of INR 4,999 from user cashback@ybl to receive payment into your bank.",
        "fake_upi_collect_request",
    ),
    (
        "qr_code_scam",
        "Scan this QR code to claim your reward of INR 2,000 immediately into your account.",
        "qr_code_scam",
    ),
    (
        "fake_refund_scam",
        "Your refund of Rs 1,499 is pending. Approve payment request in Google Pay to credit money.",
        "fake_refund_scam",
    ),
    (
        "duplicate_payment_scam",
        "Previous payment of INR 850 failed. Please pay again immediately to complete transaction.",
        "duplicate_payment_scam",
    ),
    (
        "fake_kyc_update",
        "Your SBI bank account is suspended. Update your PAN / KYC immediately at http://sbi-kyc.com",
        "fake_kyc_update",
    ),
    (
        "bank_suspension_scam",
        "Your HDFC account has been blocked due to suspicious activity. Verify now at http://hdfc-security.in",
        "bank_suspension_scam",
    ),
    (
        "fake_customer_care",
        "Dear customer, call ICICI care at 9876543210 and install AnyDesk to verify your account.",
        "fake_customer_care",
    ),
    (
        "cashback_reward_scam",
        "Congratulations! You have won Rs 5,000 scratch card. Click here to claim into UPI: http://reward.link",
        "cashback_reward_scam",
    ),
    (
        "sim_blocking_scam",
        "Your Jio SIM will be deactivated today. Call customer executive at 9988776655 to complete eKYC.",
        "sim_blocking_scam",
    ),
    (
        "electricity_disconnection_scam",
        "Your electricity power will be disconnected at 9:30 PM tonight due to unpaid bill. Call officer at 8877665544.",
        "electricity_disconnection_scam",
    ),
    (
        "fake_delivery_fee",
        "India Post: Your package is detained at depot. Pay unpaid customs fee of Rs 25 at http://indiapost-parcel.link",
        "fake_delivery_fee",
    ),
]


def test_e2e_all_12_fraud_scenarios():
    """Verifies that all 12 fraud archetypes receive explanations, token attributions, and correct verdicts."""
    sms_service = SmsClassifierService.get_instance()
    groq_service = GroqExplanationService(api_key="")  # deterministic offline verification

    for scenario_name, text, expected_category in ALL_12_FRAUD_SAMPLES:
        # 1. ML Classification & Token Attribution
        pred = sms_service.predict(text)
        assert pred.classification in ["SUSPICIOUS", "MALICIOUS"], f"Expected non-safe verdict for {scenario_name}, got {pred.classification}"
        assert len(pred.token_attributions) > 0, f"Token attribution spans missing for {scenario_name}"

        # 2. Structured XAI & Groq Reasoning
        explanation = groq_service.generate_explanation(
            text=text,
            classification=pred.classification,
            risk_score=pred.risk_score,
            reasons=pred.reasons,
            token_attributions=pred.token_attributions,
            top_risk_tokens=pred.top_risk_tokens,
        )

        assert explanation is not None
        assert explanation.fraud_type == expected_category, f"Expected {expected_category}, got {explanation.fraud_type}"
        assert len(explanation.summary_title) > 0
        assert len(explanation.why_flagged) > 0
        assert len(explanation.recommended_actions) >= 2

        # 3. Bilingual Hindi Verification
        assert explanation.hindi is not None
        assert len(explanation.hindi.summary_title) > 0
        assert len(explanation.hindi.why_flagged) > 0
        assert len(explanation.hindi.recommended_actions) >= 2


def test_e2e_clean_transactional_message():
    """Verifies that clean transactional banking SMS are classified as SAFE with no false-positive alarm."""
    clean_text = "Rs. 450.00 debited from A/c XX4021 on 09-NOV-26 at Swiggy. Available Bal: Rs 14,230.12. Ref 9283719."
    sms_service = SmsClassifierService.get_instance()
    groq_service = GroqExplanationService(api_key="")

    pred = sms_service.predict(clean_text)
    assert pred.classification == "SAFE", f"Clean transactional text false positive: {pred.classification}"
    assert pred.risk_score < 40.0

    explanation = groq_service.generate_explanation(
        text=clean_text,
        classification=pred.classification,
        risk_score=pred.risk_score,
        reasons=[],
        token_attributions=pred.token_attributions,
        top_risk_tokens=pred.top_risk_tokens,
    )

    assert explanation.fraud_type == "safe_transaction"
    assert "Verified Legitimate" in explanation.summary_title or "Legitimate" in explanation.summary_title
    assert explanation.hindi is not None


def test_e2e_upi_qr_scam_detection():
    """Verifies end-to-end UPI QR intent decoding and deceptive note trapping."""
    scam_qr = "upi://pay?pa=collect_scammer@upi&pn=Reward+Department&am=5000&tn=Scan+to+receive+Rs+5000+cashback"
    qr_decoder = QrDecoderService.get_instance()

    qr_response = qr_decoder.analyze_upi_intent(scam_qr)

    assert qr_response.payload_type.value == "upi_intent"
    assert qr_response.classification == "MALICIOUS"
    assert qr_response.risk_score >= 90.0
    assert qr_response.parsed_upi is not None
    assert qr_response.parsed_upi.pa == "collect_scammer@upi"
    assert qr_response.parsed_upi.am == 5000.0
    assert qr_response.explanation is not None
    assert qr_response.explanation.fraud_type == "qr_code_scam"


def test_e2e_upi_qr_legitimate_merchant():
    """Verifies that legitimate merchant payment QR codes are verified as SAFE."""
    safe_qr = "upi://pay?pa=starbucks@hdfcbank&pn=Starbucks+Coffee&am=350.00&mc=5812&tn=Coffee+Order"
    qr_decoder = QrDecoderService.get_instance()

    qr_response = qr_decoder.analyze_upi_intent(safe_qr)

    assert qr_response.payload_type.value == "upi_intent"
    assert qr_response.classification == "SAFE"
    assert qr_response.risk_score <= 25.0
    assert qr_response.parsed_upi is not None
    assert qr_response.parsed_upi.is_valid_format is True
    assert qr_response.parsed_upi.vpa_handle == "hdfcbank"
