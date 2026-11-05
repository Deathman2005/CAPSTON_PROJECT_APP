"""Production inference service for URL lexical risk analysis."""

import os
import json
import logging
import joblib
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from app.ml.url_features import extract_url_features_dict

logger = logging.getLogger("smsshield.ml.url_service")

ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "artifacts")
MODEL_PATH = os.path.join(ARTIFACTS_DIR, "url_classifier.joblib")
METRICS_PATH = os.path.join(ARTIFACTS_DIR, "url_model_metrics.json")


class UrlClassificationResult(BaseModel):
    """Output from the URL lexical ML inference model."""

    feature_risk_score: float = Field(..., ge=0.0, le=100.0, description="Lexical risk score (0-100)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Model prediction confidence")
    lexical_indicators: List[str] = Field(default_factory=list, description="Triggered lexical threat indicators")
    features: Dict[str, Any] = Field(default_factory=dict, description="Raw extracted lexical feature map")
    model_version: str = Field(..., description="Active URL model version identifier")
    is_fallback: bool = Field(False, description="Whether fallback heuristic was used")


class UrlClassifierService:
    """
    Production inference engine evaluating URL strings using lexical ML models.
    Zero-probing: Extracted purely from the URL structure without network traffic.
    """

    _instance: Optional["UrlClassifierService"] = None

    def __init__(self, model_path: str = MODEL_PATH, metrics_path: str = METRICS_PATH):
        self.model_path = model_path
        self.metrics_path = metrics_path
        self.pipeline = None
        self.version_id = "url_baseline_heuristic_v1"
        self.metrics: Dict[str, Any] = {}
        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """Loads serialized pipeline and evaluation metadata."""
        if os.path.exists(self.model_path):
            try:
                self.pipeline = joblib.load(self.model_path)
                logger.info(f"Loaded trained URL model artifact from {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to load URL model artifact: {e}")
                self.pipeline = None

        if os.path.exists(self.metrics_path):
            try:
                with open(self.metrics_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.version_id = data.get("version_id", self.version_id)
                    self.metrics = data.get("metrics", {})
            except Exception as e:
                logger.warning(f"Could not read URL model metrics artifact: {e}")

    @classmethod
    def get_instance(cls) -> "UrlClassifierService":
        """Singleton accessor."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def predict(self, url: str) -> UrlClassificationResult:
        """
        Evaluates lexical threat patterns in a URL string.
        Returns risk score, confidence, and human-readable indicators.
        """
        feats = extract_url_features_dict(url)
        indicators = []

        if feats["is_ip"] == 1.0:
            indicators.append("Destination is a raw IP address (commonly abused by malware/phishing servers)")
        if feats["is_shortened"] == 1.0:
            indicators.append("URL shortening service masks true destination")
        if feats["is_punycode"] == 1.0:
            indicators.append("Punycode domain detected (potential IDN homograph impersonation attack)")
        if feats["suspicious_tld"] == 1.0:
            indicators.append("Uses high-abuse top-level domain frequently seen in phishing campaigns")
        if feats["sensitive_keyword_count"] >= 2:
            indicators.append("Multiple sensitive security/banking keywords present in URL path")
        if feats["entropy"] > 4.2:
            indicators.append("High-entropy hostname indicates potential algorithmic domain generation (DGA)")
        if feats["has_at_symbol"] == 1.0:
            indicators.append("Embedded '@' symbol detected (deceptive credential redirection technique)")

        if self.pipeline is None:
            return self._heuristic_fallback(feats, indicators)

        try:
            if hasattr(self.pipeline, "predict_proba"):
                probs = self.pipeline.predict_proba([url])[0]
                phish_prob = float(probs[1])
            else:
                pred = self.pipeline.predict([url])[0]
                phish_prob = 0.95 if pred == 1 else 0.05

            risk_score = round(phish_prob * 100.0, 1)

            # Boost risk score if definitive deceptive indicators are present
            if feats["is_ip"] == 1.0:
                risk_score = max(risk_score, 75.0)
            if feats["is_punycode"] == 1.0:
                risk_score = max(risk_score, 80.0)

            confidence = round(0.70 + abs(phish_prob - 0.5) * 0.55, 2)
            confidence = min(max(confidence, 0.60), 0.99)

            return UrlClassificationResult(
                feature_risk_score=risk_score,
                confidence=confidence,
                lexical_indicators=indicators,
                features=feats,
                model_version=self.version_id,
                is_fallback=False,
            )

        except Exception as e:
            logger.error(f"Inference exception during URL prediction: {e}")
            return self._heuristic_fallback(feats, indicators)

    def _heuristic_fallback(
        self, feats: Dict[str, Any], indicators: List[str]
    ) -> UrlClassificationResult:
        """Safe heuristic fallback if model execution is unavailable."""
        score = 10.0
        if feats["is_ip"] == 1.0:
            score += 50.0
        if feats["is_shortened"] == 1.0:
            score += 30.0
        if feats["is_punycode"] == 1.0:
            score += 45.0
        if feats["suspicious_tld"] == 1.0:
            score += 25.0
        if feats["sensitive_keyword_count"] > 0:
            score += min(feats["sensitive_keyword_count"] * 15.0, 30.0)

        score = min(score, 99.0)
        confidence = 0.75 if len(indicators) > 0 else 0.85

        return UrlClassificationResult(
            feature_risk_score=score,
            confidence=confidence,
            lexical_indicators=indicators,
            features=feats,
            model_version="url_baseline_heuristic_v1",
            is_fallback=True,
        )

