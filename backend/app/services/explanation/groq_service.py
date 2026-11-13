"""Explainable AI (XAI) service powered by Groq LLM with deterministic offline fallbacks."""

import json
import logging
from typing import Optional, List, Dict, Any

from app.core.config import settings
from app.ml.preprocessor import SmsPreprocessor
from app.ml.attribution import TokenSpan
from app.services.explanation.schemas import ExplanationResult, HindiExplanation
from app.services.explanation.templates import (
    categorize_fraud_type,
    build_deterministic_explanation,
)
from app.services.explanation.prompts import (
    SYSTEM_EXPLAINER_PROMPT,
    format_user_prompt,
)

logger = logging.getLogger("smsshield.explanation.groq")


class GroqExplanationService:
    """
    Explainable AI (XAI) engine generating natural-language explanations
    and actionable safety guidance.

    Uses Groq API (llama-3.3-70b-versatile / llama-3.1-8b-instant) with
    strict response_format={"type": "json_object"}. Provides immediate,
    zero-latency deterministic fallback if API key is absent or offline.
    """

    _instance: Optional["GroqExplanationService"] = None

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        fallback_model: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        self.api_key = api_key if api_key is not None else settings.GROQ_API_KEY
        self.model = model or settings.GROQ_MODEL
        self.fallback_model = fallback_model or settings.GROQ_FALLBACK_MODEL
        self.timeout = timeout if timeout is not None else settings.GROQ_TIMEOUT_SECONDS
        self.preprocessor = SmsPreprocessor(mask_entities=True)
        self._sync_client = None

    @classmethod
    def get_instance(cls) -> "GroqExplanationService":
        """Singleton accessor."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _get_client(self):
        """Lazy initializer for Groq sync client."""
        if self._sync_client is None and self.api_key:
            try:
                from groq import Groq
                self._sync_client = Groq(
                    api_key=self.api_key,
                    timeout=self.timeout,
                )
            except Exception as e:
                logger.warning(f"Could not initialize Groq client: {e}")
                self._sync_client = None
        return self._sync_client

    def generate_explanation(
        self,
        text: str,
        classification: str,
        risk_score: float,
        reasons: Optional[List[str]] = None,
        extracted_urls: Optional[List[str]] = None,
        token_attributions: Optional[List[TokenSpan]] = None,
        top_risk_tokens: Optional[List[str]] = None,
        top_safe_tokens: Optional[List[str]] = None,
    ) -> ExplanationResult:
        """
        Generates Explainable AI reasoning for an SMS detection result.
        Returns AI-synthesized explanation if Groq is available, or
        instant deterministic domain-expert template if offline/missing key.
        """
        reasons = reasons or []
        extracted_urls = extracted_urls or []
        token_attributions = token_attributions or []
        top_risk_tokens = top_risk_tokens or []
        top_safe_tokens = top_safe_tokens or []

        # 1. Mask sensitive entity tokens (OTPs, PINs, card digits, phone numbers)
        masked_text = self.preprocessor.clean_and_normalize(text)

        # 2. Identify candidate fraud category from deterministic heuristics
        fraud_type = categorize_fraud_type(
            text=masked_text,
            reasons=reasons,
            classification=classification,
            risk_score=risk_score,
        )

        # 3. If API key is not configured, immediately use deterministic offline template
        if not self.api_key or not self.api_key.strip():
            logger.debug("GROQ_API_KEY not configured. Using deterministic explanation template.")
            return build_deterministic_explanation(
                fraud_type=fraud_type,
                classification=classification,
                risk_score=risk_score,
                evidence_reasons=reasons,
                token_attributions=token_attributions,
                top_risk_tokens=top_risk_tokens,
                top_safe_tokens=top_safe_tokens,
            )

        # 4. Attempt Groq API completion with JSON schema
        client = self._get_client()
        if client is None:
            return build_deterministic_explanation(
                fraud_type=fraud_type,
                classification=classification,
                risk_score=risk_score,
                evidence_reasons=reasons,
                token_attributions=token_attributions,
                top_risk_tokens=top_risk_tokens,
                top_safe_tokens=top_safe_tokens,
            )

        user_content = format_user_prompt(
            classification=classification,
            risk_score=risk_score,
            fraud_type_hint=fraud_type,
            reasons=reasons,
            masked_message_preview=masked_text,
            extracted_urls=extracted_urls,
            top_risk_tokens=top_risk_tokens,
        )

        # Try primary model first, then fallback model
        for target_model in [self.model, self.fallback_model]:
            try:
                chat_completion = client.chat.completions.create(
                    model=target_model,
                    messages=[
                        {"role": "system", "content": SYSTEM_EXPLAINER_PROMPT},
                        {"role": "user", "content": user_content},
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.2,
                    max_tokens=800,
                )

                raw_output = chat_completion.choices[0].message.content
                if not raw_output:
                    continue

                parsed = json.loads(raw_output)
                return self._parse_llm_json(
                    parsed,
                    fraud_type,
                    target_model,
                    token_attributions=token_attributions,
                    top_risk_tokens=top_risk_tokens,
                    top_safe_tokens=top_safe_tokens,
                )

            except Exception as exc:
                logger.warning(
                    f"Groq explanation failed on model '{target_model}': {exc}. Trying fallback..."
                )

        # 5. Fallback to deterministic template on failure
        logger.info("Groq API calls exhausted or failed; falling back to deterministic explanation.")
        return build_deterministic_explanation(
            fraud_type=fraud_type,
            classification=classification,
            risk_score=risk_score,
            evidence_reasons=reasons,
            token_attributions=token_attributions,
            top_risk_tokens=top_risk_tokens,
            top_safe_tokens=top_safe_tokens,
        )

    def _parse_llm_json(
        self,
        data: Dict[str, Any],
        fallback_fraud_type: str,
        model_name: str,
        token_attributions: Optional[List[TokenSpan]] = None,
        top_risk_tokens: Optional[List[str]] = None,
        top_safe_tokens: Optional[List[str]] = None,
    ) -> ExplanationResult:
        """Validates and constructs ExplanationResult from LLM JSON output."""
        summary_title = data.get("summary_title", "Security Threat Analysis")
        fraud_type = data.get("fraud_type") or fallback_fraud_type
        why_flagged = data.get("why_flagged", "")
        suspicious_factors = data.get("suspicious_factors", [])
        recommended_actions = data.get("recommended_actions", [])

        hindi_obj = None
        hindi_raw = data.get("hindi")
        if isinstance(hindi_raw, dict):
            hindi_obj = HindiExplanation(
                summary_title=hindi_raw.get("summary_title", "सुरक्षा विश्लेषण"),
                why_flagged=hindi_raw.get("why_flagged", ""),
                recommended_actions=list(hindi_raw.get("recommended_actions", [])),
            )

        return ExplanationResult(
            summary_title=summary_title,
            fraud_type=fraud_type,
            why_flagged=why_flagged,
            suspicious_factors=list(suspicious_factors),
            recommended_actions=list(recommended_actions),
            token_attributions=token_attributions or [],
            top_risk_tokens=top_risk_tokens or [],
            top_safe_tokens=top_safe_tokens or [],
            hindi=hindi_obj,
            model_used=model_name,
            is_ai_generated=True,
        )
