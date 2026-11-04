"""Feature extraction and linguistic signal analysis for SMS classification."""

import numpy as np
from typing import List, Dict
from sklearn.base import BaseEstimator, TransformerMixin


# Curated signal keyword dictionaries
URGENCY_KEYWORDS = {
    "urgent", "immediately", "immediate", "blocked", "suspended", "deactivated",
    "within 24 hrs", "within 24 hours", "today only", "penalty", "action required",
    "last warning", "expire", "expires", "expiring", "disconnection", "disconnected"
}

KYC_KEYWORDS = {
    "kyc", "pan", "pan card", "aadhaar", "document verification", "update kyc",
    "verify kyc", "kyc pending", "link pan", "biometric", "account update"
}

FINANCIAL_LURE_KEYWORDS = {
    "lottery", "winner", "prize", "kbc", "lucky draw", "reward", "cashback",
    "refund", "credited to account", "bonus", "crore", "lakhs", "instant loan",
    "pre-approved loan", "claim now", "won"
}

CREDENTIAL_DEMAND_KEYWORDS = {
    "send otp", "share otp", "enter otp", "verify otp", "provide otp", "submit otp",
    "enter pin", "share pin", "enter password", "netbanking password", "cvv",
    "secret code"
}

UTILITY_SCARE_KEYWORDS = {
    "electricity", "power", "bill", "disconnected tonight", "electrician", "officer",
    "power cutoff", "unpaid bill", "supply"
}

DELIVERY_LURE_KEYWORDS = {
    "parcel", "delivery", "courier", "package", "india post", "bluedart", "failed delivery",
    "update address", "redelivery fee", "customs"
}


class LinguisticFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Extracts dense linguistic and domain-specific security features from text.
    Scikit-learn compatible transformer for pipeline integration.
    """

    FEATURE_NAMES = [
        "urgency_score",
        "kyc_score",
        "financial_lure_score",
        "credential_demand_score",
        "utility_scare_score",
        "delivery_lure_score",
        "has_url_token",
        "has_phone_token",
        "has_currency_token",
        "has_code_token",
        "text_length_norm",
    ]

    def fit(self, X, y=None):
        return self

    def transform(self, X: List[str]) -> np.ndarray:
        """Transforms a list of preprocessed texts into a 2D numpy array of features."""
        features = []
        for text in X:
            text_lower = text.lower() if isinstance(text, str) else ""

            urgency_hits = sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower)
            kyc_hits = sum(1 for kw in KYC_KEYWORDS if kw in text_lower)
            financial_hits = sum(1 for kw in FINANCIAL_LURE_KEYWORDS if kw in text_lower)
            credential_hits = sum(1 for kw in CREDENTIAL_DEMAND_KEYWORDS if kw in text_lower)
            utility_hits = sum(1 for kw in UTILITY_SCARE_KEYWORDS if kw in text_lower)
            delivery_hits = sum(1 for kw in DELIVERY_LURE_KEYWORDS if kw in text_lower)

            has_url = 1.0 if "<url>" in text_lower else 0.0
            has_phone = 1.0 if "<phone>" in text_lower else 0.0
            has_currency = 1.0 if "<currency>" in text_lower else 0.0
            has_code = 1.0 if "<code>" in text_lower else 0.0
            text_len = min(len(text_lower) / 200.0, 2.0)

            features.append([
                float(urgency_hits),
                float(kyc_hits),
                float(financial_hits),
                float(credential_hits),
                float(utility_hits),
                float(delivery_hits),
                has_url,
                has_phone,
                has_currency,
                has_code,
                text_len,
            ])

        return np.array(features, dtype=np.float32)

    def get_feature_names_out(self, input_features=None):
        return np.array(self.FEATURE_NAMES)


def extract_explanation_reasons(text: str) -> List[str]:
    """Generates human-readable explanation reasons based on triggered linguistic signals."""
    reasons = []
    text_lower = text.lower()

    if any(kw in text_lower for kw in URGENCY_KEYWORDS):
        reasons.append("High urgency cues or threats of account suspension detected")

    if any(kw in text_lower for kw in KYC_KEYWORDS):
        reasons.append("Demands for KYC submission, PAN card linking, or document verification")

    if any(kw in text_lower for kw in FINANCIAL_LURE_KEYWORDS):
        reasons.append("Unsolicited lottery, prize, cashback, or loan approval lure detected")

    if any(kw in text_lower for kw in CREDENTIAL_DEMAND_KEYWORDS):
        reasons.append("Requests or lures demanding sensitive credentials (OTP, PIN, password)")

    if any(kw in text_lower for kw in UTILITY_SCARE_KEYWORDS):
        reasons.append("Utility or electricity bill disconnection scare tactic detected")

    if any(kw in text_lower for kw in DELIVERY_LURE_KEYWORDS):
        reasons.append("Package delivery failure or redelivery fee lure detected")

    if "<url>" in text_lower:
        reasons.append("Contains external hyperlink requiring inspection")

    return reasons
