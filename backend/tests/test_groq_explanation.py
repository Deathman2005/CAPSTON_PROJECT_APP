"""Unit and integration tests for Groq AI Explanation Service and deterministic fallback."""

import uuid
import json
from unittest.mock import MagicMock, patch

from app.schemas.scan import MessageScanResponse
from app.services.explanation.schemas import ExplanationResult
from app.services.explanation.templates import (
    categorize_fraud_type,
    build_deterministic_explanation,
    FRAUD_CATEGORIES,
)
from app.services.explanation.groq_service import GroqExplanationService


def test_offline_deterministic_fallback_when_no_api_key():
    """Service must return instant deterministic explanation when GROQ_API_KEY is unset."""
    service = GroqExplanationService(api_key="")
    result = service.generate_explanation(
        text="Dear customer, your SBI account will be blocked today. Update your KYC immediately.",
        classification="MALICIOUS",
        risk_score=92.0,
        reasons=["Urgent account-blocking threat", "Contains suspicious unverified domain"],
        extracted_urls=["http://sbi-kyc-verify.xyz"],
    )

    assert isinstance(result, ExplanationResult)
    assert result.is_ai_generated is False
    assert result.model_used == "deterministic_rule_engine_v1"
    assert result.fraud_type == "fake_kyc_update"
    assert "KYC" in result.summary_title
    assert len(result.recommended_actions) >= 2
    assert result.hindi is not None
    assert "केवाईसी" in result.hindi.summary_title or "खाता" in result.hindi.summary_title
    assert len(result.hindi.recommended_actions) >= 2


def test_all_12_fraud_scenarios_categorization():
    """Verify that all 12 core fraud scenarios are correctly categorized."""
    test_cases = [
        (
            "fake_payment_confirmation",
            "Payment successful! Rs 50,000 credited to your a/c. Click http://bank-pay.xyz/ack to accept funds.",
            "SUSPICIOUS",
            70.0,
        ),
        (
            "fake_upi_collect_request",
            "You received a collect request of Rs 3,000. Approve to receive payment in your account now.",
            "MALICIOUS",
            85.0,
        ),
        (
            "qr_code_scam",
            "Scan QR code using PhonePe or GPay to claim your lottery cashback of Rs 2,500 immediately.",
            "MALICIOUS",
            88.0,
        ),
        (
            "fake_refund_scam",
            "Your previous transaction failed. Claim refund of Rs 1,499 now by approving the reversal request.",
            "SUSPICIOUS",
            75.0,
        ),
        (
            "duplicate_payment_scam",
            "Earlier payment failed due to network timeout. Please pay again immediately to complete order.",
            "SUSPICIOUS",
            65.0,
        ),
        (
            "fake_kyc_update",
            "Dear SBI user, your KYC expired. Submit PAN card and Aadhaar details to avoid account freeze.",
            "MALICIOUS",
            90.0,
        ),
        (
            "bank_suspension_scam",
            "Your HDFC debit card is blocked and account suspended. Call officer within 24 hours.",
            "MALICIOUS",
            85.0,
        ),
        (
            "fake_customer_care",
            "Paytm customer care helpline: 9876543210. Download AnyDesk to resolve pending refund.",
            "MALICIOUS",
            92.0,
        ),
        (
            "cashback_reward_scam",
            "Congratulations! You won Rs 10,000 cashback reward from Google Pay. Claim prize here.",
            "SUSPICIOUS",
            78.0,
        ),
        (
            "sim_blocking_scam",
            "Dear customer, your SIM card will be deactivated tonight due to missing e-KYC documents.",
            "MALICIOUS",
            88.0,
        ),
        (
            "electricity_disconnection_scam",
            "Dear consumer, your electricity power cut tonight at 9:30 PM from electric office. Pay bill.",
            "MALICIOUS",
            91.0,
        ),
        (
            "fake_delivery_fee",
            "India Post: Your parcel shipment is on hold due to address incomplete. Pay delivery fee Rs 25.",
            "MALICIOUS",
            86.0,
        ),
        (
            "safe_transaction",
            "Your a/c XX4321 is credited with Rs 1,500 on 09-Nov-26 by UPI. Avail Bal: Rs 24,000.",
            "SAFE",
            12.0,
        ),
    ]

    for expected_category, message, classification, risk_score in test_cases:
        actual = categorize_fraud_type(
            text=message,
            reasons=[],
            classification=classification,
            risk_score=risk_score,
        )
        assert actual == expected_category, f"Failed for '{expected_category}': got '{actual}'"

        # Verify deterministic template generation
        explanation = build_deterministic_explanation(
            fraud_type=actual,
            classification=classification,
            risk_score=risk_score,
            evidence_reasons=["Heuristic pattern match"],
        )
        assert explanation.summary_title
        assert explanation.why_flagged
        assert len(explanation.recommended_actions) >= 1
        assert explanation.hindi is not None
        assert explanation.hindi.summary_title
        assert len(explanation.hindi.recommended_actions) >= 1


def test_groq_api_mock_success():
    """Verify successful parsing of Groq LLM structured JSON response."""
    mock_llm_json = {
        "summary_title": "Fake Electricity Disconnection Scam",
        "fraud_type": "electricity_disconnection_scam",
        "why_flagged": "The message creates false panic by threatening immediate power disconnection at night.",
        "suspicious_factors": [
            "Threat of immediate power shutoff tonight at 9:30 PM",
            "Personal mobile number given instead of official utility board portal",
        ],
        "recommended_actions": [
            "Do not call the number listed in the SMS.",
            "Verify your electricity bill on the official state DISCOM portal.",
        ],
        "hindi": {
            "summary_title": "बिजली बिल कनेक्शन काटने की धोखाधड़ी",
            "why_flagged": "संदेश में आज रात बिजली काटने का झूठा डर दिखाकर पैसे ऐंठने का प्रयास किया गया है।",
            "recommended_actions": [
                "संदेश में दिए गए नंबर पर कॉल न करें।",
                "अपने बिजली बिल की स्थिति केवल आधिकारिक बिजली बोर्ड वेबसाइट पर जांचें।",
            ],
        },
    }

    mock_chat_completion = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = json.dumps(mock_llm_json)
    mock_chat_completion.choices = [mock_choice]

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = mock_chat_completion

    service = GroqExplanationService(api_key="gsk_test_mock_key_12345")
    with patch.object(service, "_get_client", return_value=mock_client):
        result = service.generate_explanation(
            text="Dear user power cut tonight at 9:30 PM due to unpaid electricity bill. Contact officer.",
            classification="MALICIOUS",
            risk_score=94.0,
            reasons=["Urgent power disconnection threat"],
        )

    assert result.is_ai_generated is True
    assert result.model_used == service.model
    assert result.summary_title == "Fake Electricity Disconnection Scam"
    assert result.fraud_type == "electricity_disconnection_scam"
    assert len(result.recommended_actions) == 2
    assert result.hindi is not None
    assert result.hindi.summary_title == "बिजली बिल कनेक्शन काटने की धोखाधड़ी"


def test_groq_api_fallback_on_network_failure():
    """Verify seamless fallback to deterministic template when Groq API call raises an error."""
    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = Exception("Groq 503 Service Unavailable / Timeout")

    service = GroqExplanationService(api_key="gsk_test_failing_key")
    with patch.object(service, "_get_client", return_value=mock_client):
        result = service.generate_explanation(
            text="India Post: Your parcel is on hold due to incorrect address. Pay Rs 25 delivery fee.",
            classification="MALICIOUS",
            risk_score=87.0,
            reasons=["Phishing delivery fee demand"],
        )

    # Should not raise an exception; must gracefully fallback to deterministic template
    assert result.is_ai_generated is False
    assert result.model_used == "deterministic_rule_engine_v1"
    assert result.fraud_type == "fake_delivery_fee"
    assert "Delivery" in result.summary_title or "Courier" in result.summary_title
    assert len(result.recommended_actions) >= 2


def test_entity_redaction_before_groq():
    """Verify that phone numbers and OTP codes are redacted before LLM prompt generation."""
    service = GroqExplanationService(api_key="test_key")
    raw_message = "Your OTP is 482910 for transaction of Rs 5000. Call manager on +919876543210."
    masked = service.preprocessor.clean_and_normalize(raw_message)

    assert "482910" not in masked
    assert "+919876543210" not in masked
    assert "<code" in masked or "<currency" in masked or "<phone" in masked


def test_message_scan_response_schema_with_explanation():
    """Verify that MessageScanResponse schema integrates and serializes ExplanationResult."""
    service = GroqExplanationService(api_key="")
    explanation = service.generate_explanation(
        text="Dear customer, your SBI account will be blocked today. Update your KYC immediately.",
        classification="MALICIOUS",
        risk_score=92.0,
        reasons=["Urgent account-blocking threat", "Contains suspicious unverified domain"],
    )
    response = MessageScanResponse(
        scan_id=uuid.uuid4(),
        classification="MALICIOUS",
        confidence=0.95,
        risk_score=92.0,
        reasons=["Urgent account-blocking threat"],
        extracted_urls=[],
        recommendation="Do not share credentials.",
        model_version="sms_v1|url_v1",
        explanation=explanation,
    )
    dumped = response.model_dump()
    assert dumped["explanation"] is not None
    assert dumped["explanation"]["fraud_type"] == "fake_kyc_update"
    assert dumped["explanation"]["summary_title"] == "Fake Bank KYC Update Scam Detected"
    assert dumped["explanation"]["hindi"] is not None
    assert "केवाईसी" in dumped["explanation"]["hindi"]["summary_title"] or "खाता" in dumped["explanation"]["hindi"]["summary_title"]
