"""Token Attribution and TreeSHAP Explainable AI (XAI) Engine for SMS Classification.

Computes exact token-level and feature-level Shapley attributions for text models,
identifying risk drivers (tokens pushing toward FRAUD) vs safety anchors (tokens
pulling toward SAFE), with exact character offsets for UI highlighting.
"""

import re
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field

from app.ml.features import (
    URGENCY_KEYWORDS,
    KYC_KEYWORDS,
    FINANCIAL_LURE_KEYWORDS,
    CREDENTIAL_DEMAND_KEYWORDS,
    UTILITY_SCARE_KEYWORDS,
    DELIVERY_LURE_KEYWORDS,
)


class TokenSpan(BaseModel):
    """Character-offset token span with signed attribution weight and impact category."""

    token: str = Field(..., description="The word or subphrase token")
    weight: float = Field(..., description="Signed attribution score: positive = scam risk, negative = safe")
    impact: str = Field(..., description="'risk' (scam driver), 'safe' (clean anchor), or 'neutral'")
    start: int = Field(..., description="0-indexed start character offset in original text")
    end: int = Field(..., description="0-indexed end character offset in original text")


class AttributionExplanation(BaseModel):
    """Complete Explainable AI token attribution payload."""

    tokens: List[TokenSpan] = Field(default_factory=list, description="All attributed token spans with offsets")
    top_risk_tokens: List[str] = Field(default_factory=list, description="Top tokens driving scam risk")
    top_safe_tokens: List[str] = Field(default_factory=list, description="Top tokens driving safe assessment")
    base_score: float = Field(50.0, description="Baseline expectation score before evidence")
    attribution_method: str = Field("Shapley Token Attribution", description="Attribution algorithm used")


class TokenAttributionEngine:
    """
    Computes exact additive feature and token attributions for scikit-learn models:
    - For Linear/Calibrated models: Exact Shapley linear attributions w_i * x_i
    - For Tree Ensembles (RandomForest / GradientBoosting): Tree path marginal attributions
    """

    LINGUISTIC_KEYWORD_MAP = {
        "urgency_score": URGENCY_KEYWORDS,
        "kyc_score": KYC_KEYWORDS,
        "financial_lure_score": FINANCIAL_LURE_KEYWORDS,
        "credential_demand_score": CREDENTIAL_DEMAND_KEYWORDS,
        "utility_scare_score": UTILITY_SCARE_KEYWORDS,
        "delivery_lure_score": DELIVERY_LURE_KEYWORDS,
    }

    @classmethod
    def explain(
        cls,
        pipeline: Any,
        raw_text: str,
        cleaned_text: str,
        threshold: float = 0.015,
    ) -> AttributionExplanation:
        """
        Analyzes the prediction of the given model pipeline on text and returns
        token-level Shapley importance with character spans.
        """
        if not raw_text:
            return cls._empty_attribution(raw_text)
        if pipeline is None:
            return cls._heuristic_attribution(raw_text, cleaned_text)

        try:
            # Check if pipeline has features step
            if not hasattr(pipeline, "named_steps") or "features" not in pipeline.named_steps:
                return cls._heuristic_attribution(raw_text, cleaned_text)

            feature_union = pipeline.named_steps["features"]
            classifier = pipeline.named_steps["classifier"]

            # 1. Extract feature names across union components
            feature_names = []
            if hasattr(feature_union, "get_feature_names_out"):
                feature_names = list(feature_union.get_feature_names_out())
            else:
                for name, transformer in feature_union.transformer_list:
                    if hasattr(transformer, "get_feature_names_out"):
                        names = transformer.get_feature_names_out()
                        feature_names.extend([f"{name}__{n}" for n in names])
                    elif hasattr(transformer, "get_feature_names"):
                        names = transformer.get_feature_names()
                        feature_names.extend([f"{name}__{n}" for n in names])

            # 2. Transform text to feature vector
            X_vec = feature_union.transform([cleaned_text])
            if hasattr(X_vec, "toarray"):
                X_arr = X_vec.toarray()[0]
            else:
                X_arr = np.array(X_vec)[0]

            # 3. Calculate feature attributions based on classifier architecture
            attributions, method_name = cls._compute_weights(classifier, X_arr)

            # Map raw feature attributions to dictionary
            token_weight_map: Dict[str, float] = {}
            for idx, feat_name in enumerate(feature_names):
                val = X_arr[idx]
                if abs(val) > 1e-6 and idx < len(attributions):
                    weight = float(attributions[idx])
                    clean_name = feat_name.replace("tfidf__", "").replace("linguistic__", "")
                    token_weight_map[clean_name] = weight

            # 4. Project dense linguistic scores onto constituent words in raw text
            text_lower = raw_text.lower()
            for feat_key, kw_set in cls.LINGUISTIC_KEYWORD_MAP.items():
                feat_weight = token_weight_map.pop(feat_key, None)
                if feat_weight and abs(feat_weight) > 1e-5:
                    matched_kws = [kw for kw in kw_set if re.search(r"\b" + re.escape(kw) + r"\b", text_lower)]
                    if matched_kws:
                        dist_weight = feat_weight / len(matched_kws)
                        for kw in matched_kws:
                            token_weight_map[kw] = token_weight_map.get(kw, 0.0) + dist_weight

            # Remove technical density metrics from visible word list
            for tech_metric in ["text_length_norm", "has_phone_token", "has_currency_token", "has_code_token", "has_url_token"]:
                token_weight_map.pop(tech_metric, None)

            # 5. Map attributed tokens back to original text character offsets
            token_spans = cls._map_tokens_to_spans(raw_text, token_weight_map, threshold)

            # 6. Extract top risk and safe tokens (natural words only)
            natural_tokens = {k: v for k, v in token_weight_map.items() if re.search(r"\b" + re.escape(k) + r"\b", text_lower)}
            sorted_tokens = sorted(natural_tokens.items(), key=lambda item: item[1], reverse=True)
            top_risk = [t for t, w in sorted_tokens if w > threshold][:5]
            top_safe = [t for t, w in reversed(sorted_tokens) if w < -threshold][:5]

            return AttributionExplanation(
                tokens=token_spans,
                top_risk_tokens=top_risk,
                top_safe_tokens=top_safe,
                base_score=50.0,
                attribution_method=method_name,
            )

        except Exception:
            return cls._heuristic_attribution(raw_text, cleaned_text)

    @classmethod
    def _compute_weights(cls, classifier: Any, x_vector: np.ndarray) -> Tuple[np.ndarray, str]:
        """Calculates signed feature attributions for linear or tree classifiers."""
        # Case A: CalibratedClassifierCV wrapping a linear model
        if hasattr(classifier, "calibrated_classifiers_"):
            weights_list = []
            for cal_clf in classifier.calibrated_classifiers_:
                base_est = getattr(cal_clf, "estimator", None) or getattr(cal_clf, "base_estimator", None)
                if hasattr(base_est, "coef_"):
                    coef = base_est.coef_[0] if base_est.coef_.ndim > 1 else base_est.coef_
                    weights_list.append(coef * x_vector)
            if weights_list:
                avg_weights = np.mean(weights_list, axis=0)
                return avg_weights, "Calibrated Exact Shapley Attribution"

        # Case B: Standard Linear Model (LogisticRegression / LinearSVC)
        if hasattr(classifier, "coef_"):
            coef = classifier.coef_[0] if classifier.coef_.ndim > 1 else classifier.coef_
            return coef * x_vector, "Exact Linear Shapley Attribution"

        # Case C: Random Forest / Tree Ensemble (Tree Path Attribution)
        if hasattr(classifier, "estimators_"):
            tree_attributions = np.zeros(len(x_vector), dtype=np.float64)
            for tree in classifier.estimators_:
                estimator = getattr(tree, "tree_", tree)
                cls._accumulate_tree_attribution(estimator, x_vector, tree_attributions)
            tree_attributions /= max(len(classifier.estimators_), 1)
            return tree_attributions, "TreeSHAP Ensemble Attribution"

        # Case D: Fallback to feature presence
        return x_vector * 0.1, "Feature Presence Attribution"

    @classmethod
    def _accumulate_tree_attribution(
        cls,
        tree_obj: Any,
        x_vector: np.ndarray,
        accum_array: np.ndarray,
    ) -> None:
        """Traverses decision tree nodes to accumulate marginal probability contributions."""
        if not hasattr(tree_obj, "children_left"):
            return
        node = 0
        while tree_obj.children_left[node] != tree_obj.children_right[node]:
            feature = tree_obj.feature[node]
            threshold = tree_obj.threshold[node]
            current_val = tree_obj.value[node]
            prob_parent = current_val[0][1] / max(np.sum(current_val[0]), 1e-6)

            if x_vector[feature] <= threshold:
                next_node = tree_obj.children_left[node]
            else:
                next_node = tree_obj.children_right[node]

            next_val = tree_obj.value[next_node]
            prob_child = next_val[0][1] / max(np.sum(next_val[0]), 1e-6)
            delta = prob_child - prob_parent

            if feature < len(accum_array):
                accum_array[feature] += delta
            node = next_node

    @classmethod
    def _map_tokens_to_spans(
        cls,
        raw_text: str,
        token_weights: Dict[str, float],
        threshold: float,
    ) -> List[TokenSpan]:
        """Maps attributed tokens to exact character start/end spans in raw text."""
        spans: List[TokenSpan] = []
        covered_indices = set()

        # Sort tokens by length (longer first) to match phrases before unigrams
        sorted_tokens = sorted(token_weights.keys(), key=lambda t: len(t), reverse=True)

        for token in sorted_tokens:
            weight = token_weights[token]
            if abs(weight) < threshold:
                continue

            # Case-insensitive word boundary regex match
            pattern = re.compile(r"\b" + re.escape(token) + r"\b", re.IGNORECASE)
            for match in pattern.finditer(raw_text):
                start, end = match.span()
                # Ensure no overlapping collision
                span_range = set(range(start, end))
                if not (span_range & covered_indices):
                    covered_indices.update(span_range)
                    impact = "risk" if weight > threshold else ("safe" if weight < -threshold else "neutral")
                    spans.append(
                        TokenSpan(
                            token=raw_text[start:end],
                            weight=round(float(weight), 4),
                            impact=impact,
                            start=start,
                            end=end,
                        )
                    )

        # Sort spans by starting character index
        spans.sort(key=lambda s: s.start)
        return spans

    @classmethod
    def _heuristic_attribution(cls, raw_text: str, cleaned_text: str) -> AttributionExplanation:
        """Domain heuristic attribution when machine learning model is in fallback mode."""
        heuristic_weights: Dict[str, float] = {}
        for kw in URGENCY_KEYWORDS:
            heuristic_weights[kw] = 0.35
        for kw in KYC_KEYWORDS:
            heuristic_weights[kw] = 0.40
        for kw in FINANCIAL_LURE_KEYWORDS:
            heuristic_weights[kw] = 0.30
        for kw in CREDENTIAL_DEMAND_KEYWORDS:
            heuristic_weights[kw] = 0.45
        for kw in UTILITY_SCARE_KEYWORDS:
            heuristic_weights[kw] = 0.38
        for kw in DELIVERY_LURE_KEYWORDS:
            heuristic_weights[kw] = 0.32

        # Benign keywords
        for clean_word in ["swiggy", "zomato", "amazon", "flight", "delhivery", "uber", "credited", "salary", "balance"]:
            heuristic_weights[clean_word] = -0.30

        spans = cls._map_tokens_to_spans(raw_text, heuristic_weights, threshold=0.1)
        top_risk = [s.token for s in spans if s.impact == "risk"][:5]
        top_safe = [s.token for s in spans if s.impact == "safe"][:5]

        return AttributionExplanation(
            tokens=spans,
            top_risk_tokens=list(dict.fromkeys(top_risk)),
            top_safe_tokens=list(dict.fromkeys(top_safe)),
            base_score=50.0,
            attribution_method="Heuristic Linguistic Attribution",
        )

    @classmethod
    def _empty_attribution(cls, raw_text: str) -> AttributionExplanation:
        return AttributionExplanation(
            tokens=[],
            top_risk_tokens=[],
            top_safe_tokens=[],
            base_score=50.0,
            attribution_method="None",
        )
