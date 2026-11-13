"""Inference service for SMS text scam and phishing detection."""

import os
import json
import logging
import joblib
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from app.ml.preprocessor import SmsPreprocessor
from app.ml.features import extract_explanation_reasons
from app.ml.attribution import TokenSpan, TokenAttributionEngine, AttributionExplanation

logger = logging.getLogger("smsshield.ml.service")

ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "artifacts")
MODEL_PATH = os.path.join(ARTIFACTS_DIR, "sms_classifier.joblib")
METRICS_PATH = os.path.join(ARTIFACTS_DIR, "sms_model_metrics.json")


class SmsClassificationResult(BaseModel):
    """Result payload from the SMS ML inference engine."""

    classification: str = Field(..., description="'SAFE', 'SUSPICIOUS', or 'MALICIOUS'")
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Calibrated risk score 0-100")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Model prediction confidence")
    reasons: List[str] = Field(default_factory=list, description="Top linguistic and heuristic indicators")
    model_version: str = Field(..., description="Active model version identifier")
    preprocessed_text: str = Field(..., description="Canonical entity-masked text representation")
    token_attributions: List[TokenSpan] = Field(default_factory=list, description="Token-level Explainable AI Shapley attributions with character offsets")
    top_risk_tokens: List[str] = Field(default_factory=list, description="Top tokens driving scam probability")
    top_safe_tokens: List[str] = Field(default_factory=list, description="Top tokens driving safe assessment")
    attribution_method: str = Field("Exact Linear Shapley Attribution", description="Explainability attribution method")
    is_fallback: bool = Field(False, description="Whether fallback heuristic was used")


class SmsClassifierService:
    """
    Production inference engine for evaluating SMS messages.
    Thread-safe, loads model pipeline once, and provides fallback guarantees.
    """

    _instance: Optional["SmsClassifierService"] = None

    def __init__(self, model_path: str = MODEL_PATH, metrics_path: str = METRICS_PATH):
        self.model_path = model_path
        self.metrics_path = metrics_path
        self.preprocessor = SmsPreprocessor(mask_entities=True)
        self.pipeline = None
        self.version_id = "sms_baseline_heuristic_v1"
        self.metrics: Dict[str, Any] = {}
        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """Loads serialized pipeline and evaluation metadata."""
        if os.path.exists(self.model_path):
            try:
                self.pipeline = joblib.load(self.model_path)
                logger.info(f"Loaded trained SMS model artifact from {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to load SMS model artifact: {e}")
                self.pipeline = None

        if os.path.exists(self.metrics_path):
            try:
                with open(self.metrics_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.version_id = data.get("version_id", self.version_id)
                    self.metrics = data.get("metrics", {})
            except Exception as e:
                logger.warning(f"Could not read model metrics artifact: {e}")

    @classmethod
    def get_instance(cls) -> "SmsClassifierService":
        """Singleton accessor."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def predict(self, text: str) -> SmsClassificationResult:
        """
        Predicts scam risk on input SMS text.
        Returns calibrated risk score, classification, and linguistic explanations.
        """
        cleaned_text = self.preprocessor.clean_and_normalize(text)
        reasons = extract_explanation_reasons(cleaned_text)

        # Fallback heuristic if ML pipeline artifact is absent
        if self.pipeline is None:
            return self._heuristic_fallback(text, cleaned_text, reasons)

        try:
            # Predict probability of class 1 (scam)
            if hasattr(self.pipeline, "predict_proba"):
                probs = self.pipeline.predict_proba([cleaned_text])[0]
                scam_prob = float(probs[1])
            else:
                pred = self.pipeline.predict([cleaned_text])[0]
                scam_prob = 0.95 if pred == 1 else 0.05

            risk_score = round(scam_prob * 100.0, 1)

            # High precision calibration thresholds:
            # - Scam probability >= 0.70 or strong linguistic signals -> MALICIOUS
            # - Scam probability >= 0.40 or partial signals -> SUSPICIOUS
            # - Scam probability < 0.40 -> SAFE
            if scam_prob >= 0.70 or (scam_prob >= 0.50 and len(reasons) >= 2):
                classification = "MALICIOUS"
                confidence = round(max(scam_prob, 0.85), 2)
            elif scam_prob >= 0.35 or (scam_prob >= 0.20 and len(reasons) >= 2):
                classification = "SUSPICIOUS"
                confidence = round(0.70 + abs(scam_prob - 0.5) * 0.4, 2)
            else:
                classification = "SAFE"
                confidence = round(1.0 - scam_prob, 2)

            # Explainable AI token attribution via exact Shapley decomposition
            attribution = TokenAttributionEngine.explain(self.pipeline, text, cleaned_text)

            return SmsClassificationResult(
                classification=classification,
                risk_score=risk_score,
                confidence=confidence,
                reasons=reasons,
                model_version=self.version_id,
                preprocessed_text=cleaned_text,
                token_attributions=attribution.tokens,
                top_risk_tokens=attribution.top_risk_tokens,
                top_safe_tokens=attribution.top_safe_tokens,
                attribution_method=attribution.attribution_method,
                is_fallback=False,
            )

        except Exception as e:
            logger.error(f"Inference exception during model prediction: {e}")
            return self._heuristic_fallback(text, cleaned_text, reasons)

    def _heuristic_fallback(
        self, raw_text: str, cleaned_text: str, reasons: List[str]
    ) -> SmsClassificationResult:
        """Safe heuristic fallback if model execution is unavailable."""
        lower = cleaned_text.lower()
        has_urgent = "urgent" in lower or "blocked" in lower or "suspended" in lower
        has_kyc = "kyc" in lower or "pan" in lower
        has_url = "<url>" in lower

        if (has_urgent and has_url) or (has_kyc and has_url):
            classification = "MALICIOUS"
            risk_score = 92.0
            confidence = 0.88
        elif has_urgent or has_kyc or has_url:
            classification = "SUSPICIOUS"
            risk_score = 65.0
            confidence = 0.75
        else:
            classification = "SAFE"
            risk_score = 12.0
            confidence = 0.90

        attribution = TokenAttributionEngine._heuristic_attribution(raw_text, cleaned_text)

        return SmsClassificationResult(
            classification=classification,
            risk_score=risk_score,
            confidence=confidence,
            reasons=reasons,
            model_version="sms_baseline_heuristic_v1",
            preprocessed_text=cleaned_text,
            token_attributions=attribution.tokens,
            top_risk_tokens=attribution.top_risk_tokens,
            top_safe_tokens=attribution.top_safe_tokens,
            attribution_method=attribution.attribution_method,
            is_fallback=True,
        )
