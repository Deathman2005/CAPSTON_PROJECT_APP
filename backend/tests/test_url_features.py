"""Unit tests for URL lexical and structural feature engineering."""

import pytest
import numpy as np
from app.ml.url_features import (
    extract_url_features_dict,
    calculate_shannon_entropy,
    UrlFeatureExtractor,
)


def test_shannon_entropy_calculation():
    """Verify entropy accurately differentiates regular words from high-randomness DGA domains."""
    low_entropy = calculate_shannon_entropy("google.com")
    high_entropy = calculate_shannon_entropy("qwx9102ksjd81920z.xyz")
    assert high_entropy > low_entropy
    assert low_entropy > 0.0


def test_ip_address_host_features():
    """Verify raw IP address hostname is flagged."""
    feats = extract_url_features_dict("http://192.168.1.1:8080/admin/panel")
    assert feats["is_ip"] == 1.0
    assert feats["num_digits"] >= 4
    assert feats["has_at_symbol"] == 0.0


def test_shortener_features():
    """Verify shortened domains are flagged."""
    feats = extract_url_features_dict("https://bit.ly/3xY89fake")
    assert feats["is_shortened"] == 1.0
    assert feats["is_ip"] == 0.0


def test_punycode_features():
    """Verify Punycode IDN homograph prefix is flagged."""
    feats = extract_url_features_dict("https://xn--sbi-9o0a.com/portal")
    assert feats["is_punycode"] == 1.0


def test_suspicious_tld_and_sensitive_keywords():
    """Verify suspicious TLD and banking keywords are detected."""
    feats = extract_url_features_dict("http://sbi-kyc-verify-update.xyz/login.php")
    assert feats["suspicious_tld"] == 1.0
    assert feats["sensitive_keyword_count"] >= 3  # sbi, kyc, update, login


def test_trusted_benign_url_features():
    """Verify standard legitimate domain features."""
    feats = extract_url_features_dict("https://www.onlinesbi.sbi")
    assert feats["is_ip"] == 0.0
    assert feats["is_shortened"] == 0.0
    assert feats["is_punycode"] == 0.0
    assert feats["suspicious_tld"] == 0.0
    assert feats["is_https"] == 1.0


def test_url_feature_extractor_transformer():
    """Verify scikit-learn transformer output matrix shape and keys."""
    extractor = UrlFeatureExtractor()
    urls = [
        "https://www.google.com",
        "http://45.33.32.156/bank",
    ]
    matrix = extractor.transform(urls)
    assert isinstance(matrix, np.ndarray)
    assert matrix.shape == (2, len(UrlFeatureExtractor.FEATURE_KEYS))
    assert matrix.dtype == np.float32

