"""Unit tests for SMS text preprocessor and entity masking."""

import pytest
from app.ml.preprocessor import SmsPreprocessor


@pytest.fixture
def preprocessor():
    return SmsPreprocessor(mask_entities=True)


def test_url_masking(preprocessor: SmsPreprocessor):
    """Verify URLs are masked to <URL> token."""
    text = "Visit https://sbi-fake.com/login or www.mybank-portal.in immediately."
    cleaned = preprocessor.clean_and_normalize(text)
    assert "<url>" in cleaned
    assert "https://" not in cleaned
    assert "www.mybank-portal.in" not in cleaned


def test_phone_masking(preprocessor: SmsPreprocessor):
    """Verify 10-digit phone numbers and +91 prefixes are masked to <PHONE>."""
    text = "Call electricity officer at 9876543210 or +91 9123456789."
    cleaned = preprocessor.clean_and_normalize(text)
    assert "<phone>" in cleaned
    assert "9876543210" not in cleaned
    assert "9123456789" not in cleaned


def test_currency_masking(preprocessor: SmsPreprocessor):
    """Verify currency symbols and formats are masked to <CURRENCY>."""
    variations = [
        "Refund of Rs. 4,999 approved.",
        "Your account was credited with INR 25,000.00.",
        "Cashback of ₹500 is waiting.",
        "Win $10,000 lottery cash prize.",
    ]
    for v in variations:
        cleaned = preprocessor.clean_and_normalize(v)
        assert "<currency>" in cleaned


def test_otp_code_masking(preprocessor: SmsPreprocessor):
    """Verify 4 to 8 digit verification codes are masked to <CODE>."""
    text = "Your one time verification code is 829401. Do not share."
    cleaned = preprocessor.clean_and_normalize(text)
    assert "<code>" in cleaned
    assert "829401" not in cleaned


def test_unicode_normalization_and_whitespace(preprocessor: SmsPreprocessor):
    """Verify Unicode characters are normalized and multiple spaces collapsed."""
    text = "Urgent:\u00a0\u00a0Account   blocked!!   Verify   now."
    cleaned = preprocessor.clean_and_normalize(text)
    assert "  " not in cleaned
    assert "urgent: account blocked!! verify now." == cleaned


def test_empty_and_null_inputs(preprocessor: SmsPreprocessor):
    """Verify preprocessor handles empty and null inputs safely."""
    assert preprocessor.clean_and_normalize("") == ""
    assert preprocessor.clean_and_normalize(None) == ""


def test_extract_entity_counts(preprocessor: SmsPreprocessor):
    """Verify accurate extraction of entity counts before masking."""
    msg = "Call 9876543210 to claim Rs 5,000 refund using code 1234 at https://claim.com"
    counts = preprocessor.extract_entity_counts(msg)
    assert counts["phones"] >= 1
    assert counts["currencies"] >= 1
    assert counts["codes"] >= 1
    assert counts["urls"] >= 1
