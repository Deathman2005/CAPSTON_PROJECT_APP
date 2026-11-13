"""UPI Payment Risk and Deception Detection Engine."""

import re
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from app.services.upi.parser import UpiIntentDetails, INSTITUTIONAL_KEYWORDS, POPULAR_PSP_HANDLES


# Deceptive words commonly placed in transaction note (tn) to fool victims into scanning QR codes
CREDIT_LURE_KEYWORDS = [
    "refund", "cashback", "prize", "won", "reward", "bonus", "claim",
    "received", "credit", "credited", "advance", "incoming", "settlement",
    "money back", "accept payment", "receive money", "lottery", "gift"
]

# Personal mobile number regex (10-digit Indian phone number)
PHONE_VPA_PATTERN = re.compile(r"^(?:\+?91)?[6-9]\d{9}$")


class UpiRiskAssessment(BaseModel):
    """Complete risk verdict for an individual UPI payment intent."""

    classification: str = Field(..., description="'SAFE', 'SUSPICIOUS', or 'MALICIOUS'")
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Calibrated risk score 0 to 100")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Verdict confidence")
    indicators: List[str] = Field(default_factory=list, description="Specific risk and deception indicators")
    fraud_scenario: str = Field("qr_code_scam", description="Mapped fraud scenario identifier")
    is_p2p: bool = Field(True, description="Whether transaction targets an individual P2P account")
    is_merchant: bool = Field(False, description="Whether transaction targets an established commercial merchant")
    impersonation_detected: bool = Field(False, description="Whether institutional impersonation was identified")
    credit_lure_detected: bool = Field(False, description="Whether transaction note falsely claims incoming credit")
    recommendation: str = Field(..., description="Actionable security instruction for user")


class UpiRiskAnalyzer:
    """Analyzes UPI payment parameters for social engineering, brand impersonation, and fraudulent drain lures."""

    @classmethod
    def evaluate(cls, upi: UpiIntentDetails) -> UpiRiskAssessment:
        """Evaluates an extracted UPI payment intent for malicious deceptive patterns."""
        if not upi.is_upi or not upi.is_valid_format:
            return UpiRiskAssessment(
                classification="SUSPICIOUS",
                risk_score=70.0,
                confidence=0.85,
                indicators=["Malformed or unverified UPI URI structure", "Missing or invalid Payee VPA address"],
                fraud_scenario="qr_code_scam",
                is_p2p=True,
                is_merchant=False,
                recommendation="Do NOT scan or authorize this QR code. The payment address is invalid or corrupt.",
            )

        indicators: List[str] = []
        risk_score = 15.0  # Base score for standard UPI intent
        impersonation = False
        credit_lure = False

        pa = (upi.pa or "").lower()
        pn = (upi.pn or "").lower()
        tn = (upi.tn or "").lower()
        vpa_user = (upi.vpa_user or "").lower()
        vpa_handle = (upi.vpa_handle or "").lower()

        # Check Merchant Category Code (MCC)
        is_merchant = bool(upi.mc and upi.mc != "0000" and len(upi.mc) == 4 and upi.mc.isdigit())
        is_p2p = not is_merchant

        # 1. Check for Deceptive Credit / Refund Lures in Transaction Note (tn)
        matched_lures = [kw for kw in CREDIT_LURE_KEYWORDS if kw in tn]
        if matched_lures:
            credit_lure = True
            indicators.append(
                f"Deceptive Transaction Note: Contains '{matched_lures[0]}'. "
                "Scanning a QR code ALWAYS DEBITS money from your bank account and NEVER credits funds."
            )
            risk_score = max(risk_score, 92.0)

        # 2. Check for Institutional Impersonation in Payee Name (pn) vs Personal VPA
        matched_institutions = [kw for kw in INSTITUTIONAL_KEYWORDS if kw in pn]
        if matched_institutions:
            # If name claims to be official institution (SBI, HDFC, BESCOM, Police, India Post),
            # check if VPA is actually a personal mobile phone or personal username
            is_phone_vpa = bool(PHONE_VPA_PATTERN.match(vpa_user))
            is_personal_psp = vpa_handle in ["paytm", "ybl", "ibl", "okhdfcbank", "okaxis", "okicici", "oksbi"]

            if is_phone_vpa or (is_p2p and is_personal_psp):
                impersonation = True
                indicators.append(
                    f"Payee Impersonation Detected: Payee name claims to be '{upi.pn}' ({matched_institutions[0].upper()}), "
                    f"but the receiving account '{upi.pa}' is an individual personal wallet."
                )
                risk_score = max(risk_score, 94.0)

        # 3. Check for Suspicious PSP Handle
        if vpa_handle and vpa_handle not in POPULAR_PSP_HANDLES:
            indicators.append(f"Uncommon or unverified UPI PSP handle: @{vpa_handle}")
            risk_score += 15.0

        # 4. Check for Pre-filled High Drain Amount without Verified Merchant
        if upi.am is not None:
            if upi.am >= 25000.0 and is_p2p:
                indicators.append(f"High pre-filled personal payment amount: ₹{upi.am:,.2f}")
                risk_score = max(risk_score, 80.0)
            elif upi.am >= 5000.0 and (credit_lure or impersonation):
                indicators.append(f"Requested automatic deduction amount: ₹{upi.am:,.2f}")
                risk_score = max(risk_score, 95.0)

        # 5. Check for Embedded Secondary URL in QR
        if upi.url:
            indicators.append(f"Payment intent redirects to external invoice URL: {upi.url}")
            risk_score += 10.0

        # Final Classification & Recommendation
        risk_score = min(max(risk_score, 0.0), 100.0)

        if risk_score >= 80.0 or credit_lure or impersonation:
            classification = "MALICIOUS"
            confidence = 0.95
            scenario = "fake_refund_scam" if "refund" in tn else "qr_code_scam"
            recommendation = (
                f"DO NOT ENTER YOUR UPI PIN! Authorizing this request will immediately DEDUCT "
                f"{('₹' + str(upi.am)) if upi.am else 'funds'} from your bank account and send it to {upi.pa}."
            )
        elif risk_score >= 50.0:
            classification = "SUSPICIOUS"
            confidence = 0.80
            scenario = "qr_code_scam"
            recommendation = (
                f"Verify payee details carefully. Confirm that {upi.pa} is the exact person or merchant you intend to pay."
            )
        else:
            classification = "SAFE"
            confidence = 0.90
            scenario = "safe_transaction"
            recommendation = (
                f"Standard UPI payment intent to {upi.pn or upi.pa}. "
                f"Ensure the amount {('₹' + str(upi.am)) if upi.am else ''} matches your intended purchase."
            )

        return UpiRiskAssessment(
            classification=classification,
            risk_score=round(risk_score, 1),
            confidence=confidence,
            indicators=indicators,
            fraud_scenario=scenario,
            is_p2p=is_p2p,
            is_merchant=is_merchant,
            impersonation_detected=impersonation,
            credit_lure_detected=credit_lure,
            recommendation=recommendation,
        )

