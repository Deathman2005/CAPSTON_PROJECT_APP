"""Unit tests for domain linguistic features and explanation generator."""

import numpy as np
import pytest
from app.ml.features import (
    LinguisticFeatureExtractor,
    extract_explanation_reasons,
    URGENCY_KEYWORDS,
    KYC_KEYWORDS,
    FINANCIAL_LURE_KEYWORDS,
    CREDENTIAL_DEMAND_KEYWORDS,
    UTILITY_SCARE_KEYWORDS,
    DELIVERY_LURE_KEYWORDS,
)


def test_linguistic_feature_extractor_shape_and_names():
    """Verify transformer returns expected shape and feature names."""
    extractor = LinguisticFeatureExtractor()
    texts = [
        "urgent: sbi account suspended update kyc now at <url>",
        "dinner tonight at 7 pm with family",
    ]
    feats = extractor.transform(texts)
    assert isinstance(feats, np.ndarray)
    assert feats.shape == (2, len(LinguisticFeatureExtractor.FEATURE_NAMES))
    assert feats[0, 0] > 0  # urgency hit
    assert feats[0, 1] > 0  # kyc hit
    assert feats[0, 6] == 1.0  # has_url_token


def test_extract_explanation_reasons():
    """Verify generated explanation reasons match present cues."""
    text1 = "urgent: your bank account is blocked. update kyc at <url>"
    reasons1 = extract_explanation_reasons(text1)
    assert any("urgency" in r.lower() for r in reasons1)
    assert any("kyc" in r.lower() for r in reasons1)
    assert any("hyperlink" in r.lower() for r in reasons1)

    text2 = "power will be disconnected tonight by electricity officer"
    reasons2 = extract_explanation_reasons(text2)
    assert any("electricity" in r.lower() or "disconnection" in r.lower() for r in reasons2)

    text3 = "you won kbc lottery of <currency> claim now"
    reasons3 = extract_explanation_reasons(text3)
    assert any("lottery" in r.lower() or "prize" in r.lower() for r in reasons3)

    text4 = "hello friend how are you today"
    reasons4 = extract_explanation_reasons(text4)
    assert len(reasons4) == 0
