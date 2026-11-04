"""Unit tests for defensive URL normalizer and query parameter redactor."""

import pytest
from app.services.url.normalizer import (
    normalize_and_sanitize_url,
    strip_punctuation,
    is_ip_hostname,
    is_shortener,
)


def test_strip_punctuation():
    """Verify sentence punctuation is removed from boundaries."""
    assert strip_punctuation("https://example.com.") == "https://example.com"
    assert strip_punctuation("(https://example.com/login),") == "https://example.com/login"
    assert strip_punctuation("\"https://example.com!\"") == "https://example.com"


def test_scheme_less_url_normalization():
    """Verify scheme-less URLs default safely to http://."""
    info = normalize_and_sanitize_url("www.example.com/path")
    assert info.scheme == "http"
    assert info.hostname == "www.example.com"
    assert info.normalized_url == "http://www.example.com/path"


def test_sensitive_query_parameter_redaction():
    """Verify access tokens and passwords in query string are redacted before storage."""
    raw = "https://bank.com/reset?token=secret123&user=john&password=mypassword&auth_key=key999"
    info = normalize_and_sanitize_url(raw)

    assert "secret123" not in info.redacted_url
    assert "mypassword" not in info.redacted_url
    assert "key999" not in info.redacted_url
    assert "token=%5BREDACTED%5D" in info.redacted_url or "token=[REDACTED]" in info.redacted_url
    assert "user=john" in info.redacted_url


def test_shortener_detection():
    """Verify known shortening domains are flagged."""
    info = normalize_and_sanitize_url("https://bit.ly/3xY89")
    assert info.is_shortened is True

    info2 = normalize_and_sanitize_url("https://tinyurl.com/sbi-verify")
    assert info2.is_shortened is True

    info3 = normalize_and_sanitize_url("https://www.google.com")
    assert info3.is_shortened is False


def test_ip_address_hostname():
    """Verify IPv4 hostnames are flagged."""
    info = normalize_and_sanitize_url("http://192.168.1.1:8080/admin")
    assert info.is_ip_address is True
    assert info.hostname == "192.168.1.1"

    info2 = normalize_and_sanitize_url("http://45.33.32.156/bank")
    assert info2.is_ip_address is True


def test_punycode_idn_conversion():
    """Verify Unicode/Punycode domain handling."""
    info = normalize_and_sanitize_url("https://xn--sbi-9o0a.com/portal")
    assert info.is_punycode is True


def test_unsupported_scheme_raises():
    """Verify schemes like file:// and ftp:// are rejected."""
    with pytest.raises(ValueError, match="Unsupported URL scheme"):
        normalize_and_sanitize_url("file:///etc/passwd")

    with pytest.raises(ValueError, match="Unsupported URL scheme"):
        normalize_and_sanitize_url("ftp://internal.repo/bin")

