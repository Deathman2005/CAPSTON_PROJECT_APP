"""Text preprocessing and token normalization pipeline for SMS messages."""

import re
import unicodedata
from typing import Dict, Any


# Regular expressions for entity masking
URL_PATTERN = re.compile(
    r"\b(?:https?://|www\.)[a-zA-Z0-9.\-_]+(?::\d+)?(?:/[^\s]*)?|\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?",
    re.IGNORECASE,
)
PHONE_PATTERN = re.compile(r"(?:\+?91[\-\s]?)?[6-9]\d{9}\b|\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b")
CURRENCY_PATTERN = re.compile(
    r"(?:(?:Rs\.?|INR|₹|\$|USD|EUR|€|£)\s*[\d,]+(?:\.\d+)?)|(?:[\d,]+(?:\.\d+)?\s*(?:Rs\.?|INR|₹|dollars?|rupees?))",
    re.IGNORECASE,
)
CODE_PATTERN = re.compile(r"\b\d{4,8}\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
MULTISPACE_PATTERN = re.compile(r"\s+")


class SmsPreprocessor:
    """
    Transforms raw SMS messages into canonical representation with normalized
    semantic entity tokens (<URL>, <PHONE>, <CURRENCY>, <CODE>, <EMAIL>).
    """

    def __init__(self, mask_entities: bool = True):
        self.mask_entities = mask_entities

    def clean_and_normalize(self, text: str) -> str:
        """
        Cleans text, normalizes Unicode, replaces sensitive/variable entities with tokens,
        and standardizes whitespace.
        """
        if not text or not isinstance(text, str):
            return ""

        # 1. Unicode normalization (NFKC standard)
        normalized = unicodedata.normalize("NFKC", text)

        # 2. Entity Masking
        if self.mask_entities:
            # Mask emails first to avoid partial URL/phone overlap
            normalized = EMAIL_PATTERN.sub(" <EMAIL> ", normalized)
            # Mask URLs
            normalized = URL_PATTERN.sub(" <URL> ", normalized)
            # Mask currencies
            normalized = CURRENCY_PATTERN.sub(" <CURRENCY> ", normalized)
            # Mask phone numbers
            normalized = PHONE_PATTERN.sub(" <PHONE> ", normalized)
            # Mask standalone numeric codes/OTPs
            normalized = CODE_PATTERN.sub(" <CODE> ", normalized)

        # 3. Lowercase
        normalized = normalized.lower()

        # 4. Collapse whitespace
        normalized = MULTISPACE_PATTERN.sub(" ", normalized).strip()

        return normalized

    def extract_entity_counts(self, text: str) -> Dict[str, int]:
        """Extracts counts of identifiable entities prior to masking."""
        if not text:
            return {"urls": 0, "phones": 0, "currencies": 0, "codes": 0, "emails": 0}

        return {
            "urls": len(URL_PATTERN.findall(text)),
            "phones": len(PHONE_PATTERN.findall(text)),
            "currencies": len(CURRENCY_PATTERN.findall(text)),
            "codes": len(CODE_PATTERN.findall(text)),
            "emails": len(EMAIL_PATTERN.findall(text)),
        }
