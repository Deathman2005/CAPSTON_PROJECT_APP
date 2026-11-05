"""Lexical and structural feature extraction for URL security classification."""

import math
import re
import ipaddress
from collections import Counter
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

from app.services.url.normalizer import is_shortener

# High-risk / commonly abused top-level domains in phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "club", "buzz", "icu",
    "work", "online", "site", "vip", "fit", "link", "bid", "fun", "surf"
}

# Sensitive credential and security keywords frequently placed in deceptive URLs
SENSITIVE_URL_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "update", "kyc", "pan", "aadhaar", "banking", "bank", "account",
    "portal", "auth", "admin", "support", "refund", "claim", "password",
    "wallet", "recharge", "disconnection", "bill"
]


def calculate_shannon_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string (detects DGA / randomized domains)."""
    if not text:
        return 0.0
    entropy = 0.0
    text_len = len(text)
    counts = Counter(text)
    for count in counts.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_url_features_dict(url: str) -> Dict[str, Any]:
    """
    Extracts 18 lexical and structural features from a target URL string.
    Privacy-safe: Performs zero outbound network requests or server probing.
    """
    cleaned = url.strip()
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"http://{cleaned}"

    parsed = urlparse(cleaned)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    # 1. Length features
    url_length = len(cleaned)
    hostname_length = len(hostname)
    path_length = len(path)

    # 2. Structural punctuation counts
    num_dots = hostname.count(".")
    num_hyphens = hostname.count("-") + path.count("-")
    num_underscores = cleaned.count("_")
    num_slashes = cleaned.count("/")
    num_digits = sum(1 for c in cleaned if c.isdigit())
    digit_ratio = num_digits / max(url_length, 1)

    # 3. Subdomain analysis
    labels = [l for l in hostname.split(".") if l]
    num_subdomains = max(0, len(labels) - 2)

    # 4. Query parameters
    num_query_params = len(parse_qs(query))

    # 5. Security & Deception Indicators
    has_at_symbol = 1.0 if "@" in cleaned else 0.0

    # IP address hostname check
    try:
        ipaddress.ip_address(hostname)
        is_ip = 1.0
    except ValueError:
        is_ip = 0.0

    is_https = 1.0 if parsed.scheme == "https" else 0.0
    is_short = 1.0 if is_shortener(hostname) else 0.0
    is_puny = 1.0 if hostname.startswith("xn--") or ".xn--" in hostname else 0.0

    # Suspicious TLD check
    tld = labels[-1] if labels else ""
    suspicious_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    # Sensitive keyword occurrence in hostname or path
    url_lower = cleaned.lower()
    sensitive_keyword_count = sum(1 for kw in SENSITIVE_URL_KEYWORDS if kw in url_lower)

    # Hostname Shannon entropy
    entropy = calculate_shannon_entropy(hostname)

    return {
        "url_length": float(url_length),
        "hostname_length": float(hostname_length),
        "path_length": float(path_length),
        "num_dots": float(num_dots),
        "num_hyphens": float(num_hyphens),
        "num_underscores": float(num_underscores),
        "num_slashes": float(num_slashes),
        "num_digits": float(num_digits),
        "digit_ratio": float(round(digit_ratio, 4)),
        "num_subdomains": float(num_subdomains),
        "num_query_params": float(num_query_params),
        "has_at_symbol": has_at_symbol,
        "is_ip": is_ip,
        "is_https": is_https,
        "is_shortened": is_short,
        "is_punycode": is_puny,
        "suspicious_tld": suspicious_tld,
        "sensitive_keyword_count": float(sensitive_keyword_count),
        "entropy": float(entropy),
    }


class UrlFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Scikit-learn compatible transformer converting URL strings into a 2D feature matrix.
    """

    FEATURE_KEYS = [
        "url_length",
        "hostname_length",
        "path_length",
        "num_dots",
        "num_hyphens",
        "num_underscores",
        "num_slashes",
        "num_digits",
        "digit_ratio",
        "num_subdomains",
        "num_query_params",
        "has_at_symbol",
        "is_ip",
        "is_https",
        "is_shortened",
        "is_punycode",
        "suspicious_tld",
        "sensitive_keyword_count",
        "entropy",
    ]

    def fit(self, X, y=None):
        return self

    def transform(self, X: List[str]) -> np.ndarray:
        """Transforms a list of URLs into a 2D numpy array of lexical features."""
        matrix = []
        for url in X:
            d = extract_url_features_dict(url)
            row = [d[k] for k in self.FEATURE_KEYS]
            matrix.append(row)
        return np.array(matrix, dtype=np.float32)

    def get_feature_names_out(self, input_features=None):
        return np.array(self.FEATURE_KEYS)
