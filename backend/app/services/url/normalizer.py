"""Defensive URL normalization, sanitization, and sensitive token redaction."""

import re
import ipaddress
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
from typing import Optional
from pydantic import BaseModel


class NormalizedUrlInfo(BaseModel):
    """Normalized URL metadata and security attributes."""

    original_url: str
    normalized_url: str
    redacted_url: str
    scheme: str
    hostname: str
    port: Optional[int] = None
    path: str
    is_ip_address: bool = False
    is_shortened: bool = False
    is_punycode: bool = False


# Known URL shortener domains commonly abused in SMS phishing
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "rb.gy", "goo.gl", "bit.do", "shorte.st", "adf.ly",
    "tiny.cc", "lnkd.in", "rebrand.ly"
}

# Sensitive query parameter keys that must be redacted prior to persistence
SENSITIVE_PARAM_KEYS = {
    "token", "session", "auth", "key", "api_key", "password", "pwd",
    "secret", "sig", "signature", "access_token", "id_token", "credential"
}

# Regex to strip surrounding punctuation caught in natural language text
PUNCTUATION_STRIP_REGEX = re.compile(r"^[\(\[\<\"\']+|[\.\,\;\!\?\)\}\]\>\"\']+$")


def strip_punctuation(text: str) -> str:
    """Strips leading and trailing sentence punctuation."""
    cleaned = text.strip()
    return PUNCTUATION_STRIP_REGEX.sub("", cleaned)


def is_ip_hostname(hostname: str) -> bool:
    """Checks whether the hostname is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def is_shortener(hostname: str) -> bool:
    """Checks whether the hostname is an identified URL shortening service."""
    host_lower = hostname.lower()
    return any(host_lower == s or host_lower.endswith(f".{s}") for s in KNOWN_SHORTENERS)


def normalize_and_sanitize_url(raw_url: str) -> NormalizedUrlInfo:
    """
    Normalizes a candidate URL string, enforces valid schemes, converts hostnames to IDN/ASCII,
    and produces a redacted version with sensitive query parameters stripped.
    """
    cleaned = strip_punctuation(raw_url)
    if not cleaned:
        raise ValueError("URL string cannot be empty")

    # Check for scheme or add default http:// scheme
    if "://" in cleaned:
        candidate = cleaned
    elif any(cleaned.lower().startswith(p) for p in ("javascript:", "data:", "about:", "mailto:", "tel:", "file:")):
        scheme_prefix = cleaned.split(":", 1)[0].lower()
        raise ValueError(f"Unsupported URL scheme: {scheme_prefix}. Only HTTP and HTTPS are permitted.")
    else:
        candidate = f"http://{cleaned}"

    parsed = urlparse(candidate)
    scheme = (parsed.scheme or "http").lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {scheme}. Only HTTP and HTTPS are permitted.")

    raw_host = parsed.hostname
    if not raw_host:
        raise ValueError("URL must contain a valid hostname")

    # Convert hostname to lowercase ASCII (handles Punycode/IDN)
    try:
        hostname = raw_host.encode("idna").decode("ascii").lower()
    except Exception:
        hostname = raw_host.lower()

    is_puny = hostname.startswith("xn--") or ".xn--" in hostname
    is_ip = is_ip_hostname(hostname)
    is_short = is_shortener(hostname)

    port = parsed.port
    # Omit default ports from normalized representation
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None

    netloc = f"{hostname}:{port}" if port else hostname
    path = parsed.path or "/"

    # Build standard normalized URL
    normalized_url = urlunparse((
        scheme,
        netloc,
        path,
        parsed.params,
        parsed.query,
        ""  # Fragment stripped for canonical comparison
    ))

    # Build redacted URL for persistent storage
    redacted_query = ""
    if parsed.query:
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        redacted_pairs = []
        for k, v in query_pairs:
            if k.lower() in SENSITIVE_PARAM_KEYS or any(s in k.lower() for s in ("token", "password", "secret", "auth")):
                redacted_pairs.append((k, "[REDACTED]"))
            else:
                redacted_pairs.append((k, v))
        redacted_query = urlencode(redacted_pairs)

    redacted_url = urlunparse((
        scheme,
        netloc,
        path,
        parsed.params,
        redacted_query,
        ""
    ))

    return NormalizedUrlInfo(
        original_url=raw_url,
        normalized_url=normalized_url,
        redacted_url=redacted_url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        path=path,
        is_ip_address=is_ip,
        is_shortened=is_short,
        is_punycode=is_puny,
    )
