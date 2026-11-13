"""Unit and integration tests for QR Code Decoder and UPI Payment Intent Engine."""

import pytest
import uuid
from app.services.upi.parser import UpiIntentParser, UpiIntentDetails
from app.services.upi.risk_analyzer import UpiRiskAnalyzer, UpiRiskAssessment
from app.services.upi.qr_decoder import QrDecoderService, QrPayloadType, QrEvaluationResult
from app.schemas.qr import QrScanRequest, QrScanResponse


def test_parse_valid_upi_uri():
    """Verify syntactic decomposition of a standard NPCI UPI payment URI."""
    raw = "upi://pay?pa=chaipoint@okhdfcbank&pn=Chai%20Point&mc=5411&am=150.50&cu=INR&tn=Afternoon%20Tea"
    upi = UpiIntentParser.parse(raw)

    assert upi.is_upi is True
    assert upi.is_valid_format is True
    assert upi.pa == "chaipoint@okhdfcbank"
    assert upi.pn == "Chai Point"
    assert upi.mc == "5411"
    assert upi.am == 150.50
    assert upi.cu == "INR"
    assert upi.tn == "Afternoon Tea"
    assert upi.vpa_user == "chaipoint"
    assert upi.vpa_handle == "okhdfcbank"


def test_parse_malformed_upi_uri():
    """Verify handling of corrupt or incomplete UPI URIs."""
    raw = "upi://pay?pn=NoAddressUser&am=500"
    upi = UpiIntentParser.parse(raw)

    assert upi.is_upi is True
    assert upi.is_valid_format is False
    assert upi.pa is None


def test_qr_scam_deceptive_credit_refund_note():
    """Verify detection of the classic 'Scan QR to Receive Refund' deception."""
    raw = "upi://pay?pa=scammer88@ybl&pn=PhonePe%20Refund&am=4999.00&cu=INR&tn=REFUND_APPROVED_CLAIM_NOW"
    upi = UpiIntentParser.parse(raw)
    risk = UpiRiskAnalyzer.evaluate(upi)

    assert risk.classification == "MALICIOUS"
    assert risk.risk_score >= 90.0
    assert risk.credit_lure_detected is True
    assert any("DEBITS" in ind for ind in risk.indicators)
    assert "DO NOT ENTER YOUR UPI PIN" in risk.recommendation


def test_qr_scam_payee_impersonation():
    """Verify detection when Payee Name claims official bank but VPA is personal phone."""
    raw = "upi://pay?pa=9876543210@paytm&pn=SBI%20Customer%20Support%20Officer&am=12500.00&cu=INR"
    upi = UpiIntentParser.parse(raw)
    risk = UpiRiskAnalyzer.evaluate(upi)

    assert risk.classification == "MALICIOUS"
    assert risk.risk_score >= 90.0
    assert risk.impersonation_detected is True
    assert any("Impersonation" in ind for ind in risk.indicators)


def test_qr_legitimate_merchant_payment():
    """Verify that verified retail/merchant QR payments are marked safe with low risk score."""
    raw = "upi://pay?pa=swiggy@icici&pn=Swiggy&mc=5812&am=480.00&cu=INR&tn=Order%20Payment"
    upi = UpiIntentParser.parse(raw)
    risk = UpiRiskAnalyzer.evaluate(upi)

    assert risk.classification == "SAFE"
    assert risk.risk_score <= 25.0
    assert risk.is_merchant is True
    assert risk.impersonation_detected is False
    assert risk.credit_lure_detected is False


def test_qr_decoder_routing_upi_intent():
    """Verify QrDecoderService identifies UPI intent and generates Explainable AI explanation."""
    raw = "upi://pay?pa=scammer@paytm&pn=Electricity%20Department&am=3200&tn=Electricity_Bill_Refund"
    service = QrDecoderService.get_instance()
    res = service.analyze_upi_intent(raw)

    assert res.payload_type == QrPayloadType.UPI_INTENT
    assert res.classification == "MALICIOUS"
    assert res.parsed_upi is not None
    assert res.parsed_upi.pa == "scammer@paytm"
    assert res.explanation is not None
    assert res.explanation.hindi is not None
    assert len(res.explanation.recommended_actions) >= 2


def test_identify_qr_payload_types():
    """Verify identification of payload types."""
    assert QrDecoderService.identify_payload_type("upi://pay?pa=user@sbi") == QrPayloadType.UPI_INTENT
    assert QrDecoderService.identify_payload_type("UPI://PAY?PA=USER@SBI") == QrPayloadType.UPI_INTENT
    assert QrDecoderService.identify_payload_type("https://sbi-phishing.xyz") == QrPayloadType.URL
    assert QrDecoderService.identify_payload_type("http://example.com") == QrPayloadType.URL
    assert QrDecoderService.identify_payload_type("www.example.com") == QrPayloadType.URL
    assert QrDecoderService.identify_payload_type("WIFI:S:Network;P:pass;;") == QrPayloadType.PLAIN_TEXT


def test_qr_scan_response_schema():
    """Verify QrScanResponse serializes cleanly with Pydantic."""
    raw = "upi://pay?pa=seller@okaxis&pn=LocalStore&am=250&cu=INR"
    upi = UpiIntentParser.parse(raw)
    resp = QrScanResponse(
        scan_id=uuid.uuid4(),
        payload_type="upi_intent",
        raw_content=raw,
        parsed_upi=upi,
        classification="SAFE",
        risk_score=15.0,
        confidence=0.92,
        reasons=["Standard personal or retail UPI payment intent"],
        recommendation="Verify merchant amount.",
    )
    dumped = resp.model_dump()

    assert dumped["payload_type"] == "upi_intent"
    assert dumped["parsed_upi"]["pa"] == "seller@okaxis"
    assert dumped["classification"] == "SAFE"
    assert "timestamp" in dumped
