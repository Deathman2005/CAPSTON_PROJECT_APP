"""UPI Deep-Link Intent Parser conforming to NPCI UPI Specifications."""

import urllib.parse
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


# Well-known Indian PSP handles
POPULAR_PSP_HANDLES = {
    "okhdfcbank", "okaxis", "okicici", "oksbi", "paytm", "ybl", "ibl", "axl",
    "barodampay", "upi", "apl", "fbl", "idfcbank", "kotak", "postbank", "indus",
    "federal", "cnrb", "unionbank", "pnb", "boi", "airtel", "amazonpay", "aubank",
    "scb", "hsbc", "dbs", "rbl", "yesbank", "icici", "hdfcbank", "axisbank", "sbi"
}

# Recognized institutional / brand impersonation patterns
INSTITUTIONAL_KEYWORDS = [
    "sbi", "hdfc", "icici", "axis", "kotak", "pnb", "bob", "canara", "union bank",
    "bank", "electricity", "bescom", "tneb", "discom", "power", "bijli", "water",
    "post office", "india post", "courier", "customs", "tax", "income tax",
    "police", "cyber cell", "telecom", "airtel", "jio", "vi", "support",
    "customer care", "helpdesk", "refund", "lottery", "kbc", "prime minister", "yojana"
]


class UpiIntentDetails(BaseModel):
    """Structured decomposition of an NPCI UPI payment intent URI."""

    is_upi: bool = Field(True, description="Whether the payload is a valid UPI scheme")
    pa: Optional[str] = Field(None, description="Payee VPA / UPI ID (e.g. merchant@okhdfcbank)")
    pn: Optional[str] = Field(None, description="Payee display name")
    mc: Optional[str] = Field(None, description="Merchant Category Code (MCC)")
    tr: Optional[str] = Field(None, description="Transaction Reference ID")
    tn: Optional[str] = Field(None, description="Transaction Note / Description")
    am: Optional[float] = Field(None, description="Requested payment amount")
    cu: str = Field("INR", description="Currency code (defaults to INR)")
    mode: Optional[str] = Field(None, description="QR mode (e.g. 02 for static QR, 04 for dynamic QR)")
    url: Optional[str] = Field(None, description="Embedded invoice or merchant URL")
    vpa_user: Optional[str] = Field(None, description="Username part of VPA (before @)")
    vpa_handle: Optional[str] = Field(None, description="PSP handle of VPA (after @)")
    is_valid_format: bool = Field(True, description="Whether essential UPI fields are syntactically valid")
    raw_uri: str = Field(..., description="Original raw UPI intent string")


class UpiIntentParser:
    """Parses and normalizes NPCI UPI payment URIs."""

    @classmethod
    def is_upi_uri(cls, text: str) -> bool:
        """Checks if string starts with upi:// scheme."""
        if not text or not isinstance(text, str):
            return False
        stripped = text.strip().lower()
        return stripped.startswith("upi://pay") or stripped.startswith("upi://")

    @classmethod
    def parse(cls, raw_uri: str) -> UpiIntentDetails:
        """
        Parses an NPCI standard UPI URI (e.g. upi://pay?pa=...&pn=...&am=...).
        Handles URL-encoded query strings and parameters.
        """
        raw_uri_clean = raw_uri.strip() if raw_uri else ""
        if not cls.is_upi_uri(raw_uri_clean):
            return UpiIntentDetails(
                is_upi=False,
                is_valid_format=False,
                raw_uri=raw_uri_clean,
            )

        # Parse query string
        parsed = urllib.parse.urlparse(raw_uri_clean)
        query_str = parsed.query
        params = urllib.parse.parse_qs(query_str, keep_blank_values=True)

        def get_single(key: str) -> Optional[str]:
            vals = params.get(key)
            if vals and len(vals) > 0 and vals[0].strip():
                return urllib.parse.unquote(vals[0].strip())
            return None

        pa = get_single("pa")
        pn = get_single("pn")
        mc = get_single("mc")
        tr = get_single("tr")
        tn = get_single("tn")
        cu = get_single("cu") or "INR"
        mode = get_single("mode")
        url_param = get_single("url")

        # Parse amount
        am_val: Optional[float] = None
        am_raw = get_single("am")
        if am_raw:
            try:
                am_val = round(float(am_raw), 2)
            except ValueError:
                am_val = None

        # Decompose VPA
        vpa_user = None
        vpa_handle = None
        is_valid = True

        if pa:
            pa_lower = pa.lower().strip()
            if "@" in pa_lower:
                parts = pa_lower.split("@", 1)
                vpa_user = parts[0]
                vpa_handle = parts[1]
            else:
                is_valid = False
        else:
            is_valid = False

        return UpiIntentDetails(
            is_upi=True,
            pa=pa,
            pn=pn,
            mc=mc,
            tr=tr,
            tn=tn,
            am=am_val,
            cu=cu,
            mode=mode,
            url=url_param,
            vpa_user=vpa_user,
            vpa_handle=vpa_handle,
            is_valid_format=is_valid,
            raw_uri=raw_uri_clean,
        )
