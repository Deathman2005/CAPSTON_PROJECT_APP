"""Unit tests for URL inference service and lexical scoring."""

import pytest
from app.ml.url_service import UrlClassifierService, UrlClassificationResult


@pytest.fixture
def service():
    return UrlClassifierService.get_instance()


def test_predict_phishing_url(service: UrlClassifierService):
    """Verify phishing URL with deceptive traits receives high lexical risk score."""
    url = "http://sbi-kyc-verify-update.xyz/login.php"
    result = service.predict(url)
    assert isinstance(result, UrlClassificationResult)
    assert result.feature_risk_score >= 60.0
    assert result.confidence > 0.60
    assert len(result.lexical_indicators) > 0


def test_predict_benign_trusted_url(service: UrlClassifierService):
    """Verify trusted banking or global domain receives low lexical risk score."""
    url = "https://www.onlinesbi.sbi"
    result = service.predict(url)
    assert isinstance(result, UrlClassificationResult)
    assert result.feature_risk_score <= 40.0


def test_predict_raw_ip_url(service: UrlClassifierService):
    """Verify raw IP host is flagged with elevated risk."""
    url = "http://45.33.32.156/bank-login"
    result = service.predict(url)
    assert result.feature_risk_score >= 70.0
    assert any("raw IP" in ind for ind in result.lexical_indicators)


def test_url_service_fallback_resilience():
    """Verify URL service falls back safely when artifact is unavailable."""
    service = UrlClassifierService(model_path="non_existent.joblib", metrics_path="non_existent.json")
    assert service.pipeline is None

    res = service.predict("http://192.168.1.1:8080/admin")
    assert res.is_fallback is True
    assert res.feature_risk_score >= 50.0
    assert len(res.lexical_indicators) > 0
