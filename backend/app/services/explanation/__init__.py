"""Explainable AI (XAI) service package."""

from app.services.explanation.schemas import ExplanationResult, HindiExplanation
from app.services.explanation.templates import (
    FRAUD_CATEGORIES,
    categorize_fraud_type,
    build_deterministic_explanation,
)
from app.services.explanation.groq_service import GroqExplanationService

__all__ = [
    "ExplanationResult",
    "HindiExplanation",
    "FRAUD_CATEGORIES",
    "categorize_fraud_type",
    "build_deterministic_explanation",
    "GroqExplanationService",
]

