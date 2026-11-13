"""Deterministic explainability templates and fraud categorization engine.

Provides zero-latency, offline-safe, domain-expert explanations and safety
guidance in both English and Hindi across 12 distinct Indian financial scam types.
"""

import re
from typing import Dict, Any, List, Optional
from app.ml.attribution import TokenSpan
from app.services.explanation.schemas import ExplanationResult, HindiExplanation


FRAUD_CATEGORIES = {
    "fake_payment_confirmation": "Fake Payment Confirmation Scam",
    "fake_upi_collect_request": "Fake UPI Collect Request Scam",
    "qr_code_scam": "QR-Code Payment Scam",
    "fake_refund_scam": "Fake Refund Scam",
    "duplicate_payment_scam": "Duplicate Payment Scam",
    "fake_kyc_update": "Fake KYC Update SMS",
    "bank_suspension_scam": "Bank Account Suspension Scam",
    "fake_customer_care": "Fake Customer Care / Remote Access Scam",
    "cashback_reward_scam": "Cashback and Lottery Reward Scam",
    "sim_blocking_scam": "SIM Card Disconnection Scam",
    "electricity_disconnection_scam": "Electricity Bill Disconnection Scam",
    "fake_delivery_fee": "Fake Delivery / Courier Fee Scam",
    "safe_transaction": "Legitimate / Safe Transactional Message",
    "general_suspicious": "Unverified / Suspicious Message",
    "general_malicious": "Malicious Phishing Attempt",
}


def categorize_fraud_type(
    text: str,
    reasons: List[str] = None,
    classification: str = "UNKNOWN",
    risk_score: float = 50.0,
) -> str:
    """
    Identifies the primary fraud category from SMS content, detected indicators,
    and risk severity.
    """
    lower = text.lower() if text else ""
    reasons_text = " ".join(reasons or []).lower()
    combined = f"{lower} {reasons_text}"

    # If classified clean with low score, return safe transaction
    if classification == "SAFE" or risk_score < 30.0:
        return "safe_transaction"

    # 1. Electricity Bill Disconnection
    if any(k in combined for k in ["electricity", "power cut", "disconnected tonight", "bijli", "light cut", "sdpo", "electric office"]):
        return "electricity_disconnection_scam"

    # 2. SIM Blocking / Telecom e-KYC
    if any(k in combined for k in ["sim card", "sim block", "sim will be deactivated", "e-kyc", "telecom kyc", "jio doc", "airtel doc", "vi kyc"]):
        return "sim_blocking_scam"

    # 3. Delivery Fee / Courier Scam
    if any(k in combined for k in ["parcel", "courier", "delivery", "shipment", "address incomplete", "india post", "bluedart", "delhivery", "dispatch fee", "customs fee"]):
        return "fake_delivery_fee"

    # 4. QR Code Scam
    if any(k in combined for k in ["scan qr", "qr code", "scan this code", "scan to receive", "scan for refund", "qr to accept"]):
        return "qr_code_scam"

    # 5. Fake UPI Collect Request
    if any(k in combined for k in ["collect request", "approve to receive", "accept request to get", "enter upi pin to receive", "approve request to credit", "request to pay"]):
        return "fake_upi_collect_request"

    # 6. Fake Customer Care / Remote Access (Higher priority than general refund/help keywords)
    if any(k in combined for k in ["customer care", "helpline", "support executive", "toll free", "anydesk", "quicksupport", "teamviewer", "rustdesk"]):
        return "fake_customer_care"

    # 7. Fake Refund Scam
    if any(k in combined for k in ["refund", "reimbursement", "claim refund", "refund pending", "reversal request", "money back approval"]):
        return "fake_refund_scam"

    # 8. Duplicate Payment Scam
    if any(k in combined for k in ["duplicate payment", "pay again", "earlier payment failed", "first payment failed", "retry payment immediately", "double debit"]):
        return "duplicate_payment_scam"

    # 9. Fake KYC Update
    if any(k in combined for k in ["kyc", "pan card", "aadhaar", "update kyc", "kyc expired", "verify kyc", "submit pan", "c-kyc"]):
        return "fake_kyc_update"

    # 10. Bank Suspension / Account Blocking
    if any(k in combined for k in [
        "account blocked", "account suspended", "debit card blocked", "netbanking blocked",
        "frozen within 24", "temporarily suspended", "dormant account", "has been blocked",
        "account has been blocked", "account will be blocked", "blocked due to", "suspended due to",
        "card has been blocked"
    ]):
        return "bank_suspension_scam"

    # 11. Cashback & Reward Scam
    if any(k in combined for k in ["cashback", "reward", "lottery", "congratulations won", "won rs", "scratch card", "claim prize", "lucky draw"]):
        return "cashback_reward_scam"

    # 12. Fake Payment Confirmation
    if any(k in combined for k in ["credited to your", "transferred to your a/c", "payment successful", "money sent", "received payment", "credited with rs"]) and ("<url>" in combined or "http" in combined or "www." in combined or risk_score >= 50.0):
        return "fake_payment_confirmation"

    # Fallbacks based on classification
    if classification == "MALICIOUS" or risk_score >= 75.0:
        return "general_malicious"
    return "general_suspicious"


DETERMINISTIC_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "fake_payment_confirmation": {
        "summary_title": "Fake Payment Confirmation Scam Detected",
        "why_flagged": (
            "The message claims that funds have been credited or transferred to your account. "
            "Scammers frequently send forged SMS messages or fake payment confirmations to trick sellers "
            "and service providers into parting with goods or cash without actual money being transferred."
        ),
        "suspicious_factors": [
            "Payment confirmation received via an unverified sender or containing suspicious external links",
            "Missing standard Bank/NPCI reference number (UTR / RRN) or bank identifier",
            "Urges immediate release of goods or cash based solely on SMS text",
        ],
        "recommended_actions": [
            "Check your official bank or UPI mobile application directly to confirm your updated balance.",
            "Do NOT rely on SMS or screenshots as proof of payment.",
            "Never release goods, services, or cryptocurrency until the money is confirmed in your bank statement.",
        ],
        "hindi": {
            "summary_title": "फर्जी भुगतान पुष्टिकरण (Fake Payment) धोखाधड़ी",
            "why_flagged": (
                "संदेश में दावा किया गया है कि आपके खाते में पैसे ट्रांसफर कर दिए गए हैं। "
                "धोखेबाज अक्सर बिना पैसे भेजे सामान या नकद प्राप्त करने के लिए ऐसे जाली एसएमएस भेजते हैं।"
            ),
            "recommended_actions": [
                "अपने आधिकारिक बैंक या यूपीआई ऐप में जाकर तुरंत अपना बैंक बैलेंस चेक करें।",
                "केवल एसएमएस या स्क्रीनशॉट को भुगतान का पुख्ता प्रमाण न मानें।",
                "बैंक खाते में राशि जमा होने की पुष्टि से पहले सामान या पैसे किसी को न सौंपें।",
            ],
        },
    },

    "fake_upi_collect_request": {
        "summary_title": "Fake UPI Collect Request Scam Detected",
        "why_flagged": (
            "The message asks you to approve a payment request or enter your UPI PIN to 'receive' money. "
            "In the UPI architecture, you NEVER need to enter your UPI PIN or approve a request to receive money; "
            "entering your PIN always DEBITS funds from your bank account."
        ),
        "suspicious_factors": [
            "Deceptive claim that approving a request will deposit money into your account",
            "Requests entering UPI PIN or approving a collect request for incoming funds",
            "Uses urgent phrasing to pressure you into immediate action",
        ],
        "recommended_actions": [
            "Decline / Reject the collect request in your UPI application immediately.",
            "NEVER enter your UPI PIN to receive money. UPI PIN is strictly for sending money.",
            "Block the sender's VPA / UPI ID in your payment app and report it as fraud.",
        ],
        "hindi": {
            "summary_title": "फर्जी यूपीआई कलेक्ट रिक्वेस्ट धोखाधड़ी",
            "why_flagged": (
                "संदेश में पैसे प्राप्त करने के लिए कलेक्ट रिक्वेस्ट स्वीकार करने या यूपीआई पिन दर्ज करने को कहा गया है। "
                "यूपीआई नियमों के तहत पैसे पाने के लिए कभी भी पिन दर्ज करने की आवश्यकता नहीं होती; पिन डालने से पैसे कटते हैं।"
            ),
            "recommended_actions": [
                "यूपीआई ऐप में इस कलेक्ट रिक्वेस्ट को तुरंत डिक्लाइन (अस्वीकार) करें।",
                "पैसे प्राप्त करने के लिए कभी भी अपना यूपीआई पिन न डालें।",
                "पेमेंट ऐप में संदिग्ध यूपीआई आईडी को ब्लॉक करें और फ्रॉड की रिपोर्ट करें।",
            ],
        },
    },

    "qr_code_scam": {
        "summary_title": "QR-Code Payment Scam Detected",
        "why_flagged": (
            "The message directs you to scan a QR code to receive a refund, reward, or payment. "
            "Scanning a payment QR code and confirming it will DEBIT money from your bank account, never credit it."
        ),
        "suspicious_factors": [
            "Prompts scanning a QR code to claim incoming money or cash prize",
            "Combines QR code instructions with urgent or prize-winning incentives",
            "Lacks official banking channel verification",
        ],
        "recommended_actions": [
            "Do NOT scan the QR code under any circumstances.",
            "Remember: Scanning a QR code is exclusively for paying money out, never for receiving funds.",
            "Block and report the contact immediately.",
        ],
        "hindi": {
            "summary_title": "क्यूआर कोड (QR Code) धोखाधड़ी",
            "why_flagged": (
                "संदेश में इनाम, रिफंड या पैसे प्राप्त करने के लिए क्यूआर कोड स्कैन करने को कहा गया है। "
                "क्यूआर कोड स्कैन करके पिन डालने से आपके खाते से पैसे कटते हैं, पैसे कभी आते नहीं हैं।"
            ),
            "recommended_actions": [
                "संदिग्ध क्यूआर कोड को बिल्कुल भी स्कैन न करें।",
                "याद रखें: क्यूआर कोड केवल भुगतान करने के लिए होता है, पैसे पाने के लिए नहीं।",
                "संदिग्ध नंबर या प्रेषक को तुरंत ब्लॉक और रिपोर्ट करें।",
            ],
        },
    },

    "fake_refund_scam": {
        "summary_title": "Fake Refund Scam Detected",
        "why_flagged": (
            "The message claims that an earlier transaction failed and you are owed an immediate refund "
            "via a web link or payment approval. Genuine refunds are processed automatically back to your "
            "original payment method without requiring external link visits or PIN entry."
        ),
        "suspicious_factors": [
            "Requires user interaction or approval to process an automatic refund",
            "Contains an unverified web link for refund processing",
            "Impersonates shopping portals, airlines, or payment providers",
        ],
        "recommended_actions": [
            "Do NOT click on the link or approve any incoming refund approval requests.",
            "Check the refund status directly in the official merchant app or bank statement.",
            "Contact official customer support using verified numbers listed on the company website.",
        ],
        "hindi": {
            "summary_title": "फर्जी रिफंड (Fake Refund) घोटाला",
            "why_flagged": (
                "संदेश में दावा किया गया है कि आपका पिछला भुगतान विफल हो गया है और लिंक के माध्यम से रिफंड दिया जा रहा है। "
                "वास्तविक रिफंड आपके बैंक खाते में स्वतः वापस आता है, इसके लिए किसी लिंक या पिन की आवश्यकता नहीं होती।"
            ),
            "recommended_actions": [
                "संदेश में दिए गए किसी भी लिंक पर क्लिक न करें।",
                "रिफंड की स्थिति जानने के लिए सीधे संबंधित ऐप या आधिकारिक वेबसाइट पर जाएं।",
                "किसी भी अज्ञात व्यक्ति के साथ बैंक विवरण या ओटीपी साझा न करें।",
            ],
        },
    },

    "duplicate_payment_scam": {
        "summary_title": "Duplicate Payment Scam Detected",
        "why_flagged": (
            "The message falsely asserts that your previous transaction was incomplete or failed, "
            "urging you to pay again immediately. Scammers use this tactic to extract duplicate payments "
            "from unsuspecting victims."
        ),
        "suspicious_factors": [
            "Urgent demand to retry payment outside normal banking channels",
            "Vague transaction details without matching bank reference number",
            "Contains unofficial payment links or recipient VPAs",
        ],
        "recommended_actions": [
            "Check your official bank account statement or passbook to see if the first payment was debited.",
            "Do NOT initiate another payment through links provided in the SMS.",
            "If the original amount was deducted, wait 2-3 business days for bank auto-reversal.",
        ],
        "hindi": {
            "summary_title": "दोहरा भुगतान (Duplicate Payment) धोखाधड़ी",
            "why_flagged": (
                "संदेश में दावा किया गया है कि आपका पिछला भुगतान विफल रहा और तुरंत दोबारा भुगतान करें। "
                "धोखेबाज इस बहाने पीड़ितों से दोबारा पैसे वसूलने का प्रयास करते हैं।"
            ),
            "recommended_actions": [
                "अपने बैंक स्टेटमेंट में चेक करें कि क्या पहले वाला पैसा कट चुका है।",
                "एसएमएस में दिए गए लिंक से दोबारा भुगतान बिल्कुल न करें।",
                "यदि पैसा कट गया है, तो बैंक के स्वतः निपटान का इंतजार करें या बैंक से संपर्क करें।",
            ],
        },
    },

    "fake_kyc_update": {
        "summary_title": "Fake Bank KYC Update Scam Detected",
        "why_flagged": (
            "The message threatens that your bank account, net banking, or debit card will be blocked "
            "unless you update your KYC documents via the provided link. Legitimate banks never send "
            "SMS links requesting customer PAN, Aadhaar, password, or OTP details."
        ),
        "suspicious_factors": [
            "Threat of immediate account blocking or deactivation",
            "Unsolicited request to submit sensitive KYC documents via a web link",
            "Use of unofficial domains mimicking leading Indian banks",
        ],
        "recommended_actions": [
            "Do NOT click the link and never upload PAN, Aadhaar, or net banking passwords.",
            "Verify your KYC status directly by logging into your official bank mobile app or visiting a branch.",
            "Report the fraud attempt to 1930 (National Cyber Crime Helpline) or cybercrime.gov.in.",
        ],
        "hindi": {
            "summary_title": "फर्जी बैंक केवाईसी अपडेट धोखाधड़ी",
            "why_flagged": (
                "संदेश में आपका बैंक खाता ब्लॉक होने का डर दिखाकर दिए गए लिंक पर केवाईसी अपडेट करने को कहा गया है। "
                "बैंक कभी भी एसएमएस लिंक के जरिए पैन, आधार, पासवर्ड या ओटीपी नहीं मांगते।"
            ),
            "recommended_actions": [
                "संदेश में दिए गए लिंक पर कतई क्लिक न करें।",
                "अपनी केवाईसी स्थिति की पुष्टि केवल आधिकारिक बैंकिंग ऐप या बैंक शाखा में जाकर करें।",
                "साइबर हेल्पलाइन 1930 या cybercrime.gov.in पर तुरंत शिकायत दर्ज करें।",
            ],
        },
    },

    "bank_suspension_scam": {
        "summary_title": "Bank Account Suspension Threat Scam",
        "why_flagged": (
            "The message uses panic-inducing language threatening that your bank account or card "
            "will be terminated or suspended within 24 hours. Scammers exploit fear to make you click "
            "malicious phishing portals that harvest your banking credentials."
        ),
        "suspicious_factors": [
            "High urgency / panic threats (e.g., 'suspended today', 'within 24 hours')",
            "Directs to an unverified third-party link or personal phone number",
            "Originates from an unverified 10-digit mobile number rather than an official bank SMS header",
        ],
        "recommended_actions": [
            "Do NOT call the numbers or click links provided in the SMS.",
            "Log in to your verified bank app (e.g. YONO SBI, iMobile, HDFC MobileBanking) to check account status.",
            "Block the sender number immediately.",
        ],
        "hindi": {
            "summary_title": "बैंक खाता निलंबन धमकी धोखाधड़ी",
            "why_flagged": (
                "संदेश में आपका बैंक खाता या कार्ड 24 घंटे में बंद होने की धमकी देकर घबराहट पैदा की गई है। "
                "धोखेबाज डर का फायदा उठाकर आपकी नेटबैंकिंग क्रेडेंशियल चुराने के लिए ऐसे लिंक भेजते हैं।"
            ),
            "recommended_actions": [
                "एसएमएस में दिए गए नंबरों पर कॉल न करें और न ही लिंक पर क्लिक करें।",
                "खाते की सही स्थिति जानने के लिए केवल अपने बैंक के आधिकारिक ऐप में लॉगिन करें।",
                "संदिग्ध प्रेषक को तुरंत ब्लॉक करें।",
            ],
        },
    },

    "fake_customer_care": {
        "summary_title": "Fake Customer Support / Remote Access Scam",
        "why_flagged": (
            "The message impersonates support staff or customer helpline, instructing you to call an unofficial "
            "number or install remote-access software (e.g., AnyDesk, TeamViewer, QuickSupport). "
            "Once installed, scammers can view your screen and steal your banking OTPs and passwords."
        ),
        "suspicious_factors": [
            "Unverified 10-digit mobile phone listed as customer care helpline",
            "Requests installation of screen-sharing or remote management apps",
            "Demands sharing of one-time passwords (OTP) or screen access",
        ],
        "recommended_actions": [
            "NEVER install AnyDesk, TeamViewer, RustDesk, or QuickSupport at anyone's request.",
            "NEVER share OTPs, UPI PINs, or screen contents with anyone claiming to be support staff.",
            "Find genuine support numbers only on the company's verified official website.",
        ],
        "hindi": {
            "summary_title": "फर्जी कस्टमर केयर / रिमोट एक्सेस धोखाधड़ी",
            "why_flagged": (
                "संदेश में फर्जी कस्टमर केयर नंबर देकर संपर्क करने या स्क्रीन-शेयरिंग ऐप डाउनलोड करने को कहा गया है। "
                "AnyDesk या QuickSupport जैसे ऐप्स से धोखेबाज आपके फोन की स्क्रीन देखकर बैंक ओटीपी चुरा लेते हैं।"
            ),
            "recommended_actions": [
                "किसी के भी कहने पर AnyDesk, TeamViewer या QuickSupport ऐप इंस्टॉल न करें।",
                "अपना बैंक ओटीपी, पासवर्ड या स्क्रीन एक्सेस किसी के साथ साझा न करें।",
                "कस्टमर केयर का असली नंबर केवल कंपनी की आधिकारिक वेबसाइट से ही प्राप्त करें।",
            ],
        },
    },

    "cashback_reward_scam": {
        "summary_title": "Cashback / Prize Reward Scam Detected",
        "why_flagged": (
            "The message claims that you have won unexpected cashback, lottery winnings, or an expensive reward, "
            "prompting you to click a link to claim it. Legitimate rewards do not require visiting third-party links "
            "or paying an 'activation fee'."
        ),
        "suspicious_factors": [
            "Unsolicited prize, lottery, or high-value cashback claim",
            "Requires clicking an unverified link to 'claim' or 'activate' reward",
            "May request a nominal fee or UPI PIN entry to transfer the reward",
        ],
        "recommended_actions": [
            "Do NOT click on the reward link.",
            "Remember: Legitimate cashback is credited directly to your payment app without clicking links.",
            "Never pay any 'processing fee' or 'GST' to claim a prize.",
        ],
        "hindi": {
            "summary_title": "कैशबैक और लॉटरी इनाम धोखाधड़ी",
            "why_flagged": (
                "संदेश में आपको भारी कैशबैक या लॉटरी जीतने का लालच देकर लिंक पर क्लिक करने को कहा गया है। "
                "असली कैशबैक बिना किसी बाहरी लिंक या 'प्रोसेसिंग फीस' के सीधे ऐप में जमा होता है।"
            ),
            "recommended_actions": [
                "इनाम पाने के लिए दिए गए लिंक पर बिल्कुल क्लिक न करें।",
                "याद रखें: कोई भी वैध कंपनी पुरस्कार देने के लिए आपसे पैसे या पिन नहीं मांगती।",
                "संदेश को नजरअंदाज करें और प्रेषक को ब्लॉक करें।",
            ],
        },
    },

    "sim_blocking_scam": {
        "summary_title": "SIM Card Disconnection Scam Detected",
        "why_flagged": (
            "The message threatens that your SIM card or mobile services will be deactivated tonight unless "
            "you complete immediate document verification or call an unverified executive number. "
            "Telecom providers do not disconnect SIM cards via casual SMS with personal contact numbers."
        ),
        "suspicious_factors": [
            "Threat of immediate mobile number deactivation within hours",
            "Provides a personal 10-digit mobile number for 'telecom verification'",
            "Prompts downloading an APK or visiting an unverified portal",
        ],
        "recommended_actions": [
            "Do NOT call the number listed in the SMS or click any verification links.",
            "Verify your SIM connection status directly in your official operator app (MyJio, Airtel Thanks, Vi App).",
            "Visit an official telecom store in person if you suspect any legitimate document requirements.",
        ],
        "hindi": {
            "summary_title": "सिम कार्ड ब्लॉक धमकी घोटाला",
            "why_flagged": (
                "संदेश में धमकी दी गई है कि ई-केवाईसी न कराने पर आपकी सिम आज रात बंद कर दी जाएगी। "
                "दूरसंचार कंपनियां इस तरह व्यक्तिगत मोबाइल नंबरों से एसएमएस भेजकर सिम बंद नहीं करतीं।"
            ),
            "recommended_actions": [
                "संदेश में दिए गए नंबर पर कॉल न करें और न ही कोई ऐप डाउनलोड करें।",
                "सिम स्थिति की जांच केवल अपने ऑपरेटर के आधिकारिक ऐप (MyJio, Airtel Thanks, Vi) में करें।",
                "आवश्यकता पड़ने पर नजदीकी आधिकारिक ऑपरेटर स्टोर पर जाएं।",
            ],
        },
    },

    "electricity_disconnection_scam": {
        "summary_title": "Electricity Bill Disconnection Scam Detected",
        "why_flagged": (
            "The message warns that your home electricity will be disconnected tonight at 9:30 PM due to an "
            "unpaid bill, urging you to contact a fake 'electricity officer' number or click a link. "
            "State electricity boards never issue disconnection threats via unofficial personal mobile numbers."
        ),
        "suspicious_factors": [
            "Specific deadline threat (e.g. 'power cut tonight at 9:30 PM')",
            "Personal 10-digit mobile number provided for electricity officer contact",
            "Urges instant payment via non-standard links or downloading malicious APKs",
        ],
        "recommended_actions": [
            "Do NOT call the electricity officer number or pay through the SMS link.",
            "Check your bill status on your state electricity board's official website or electricity board app.",
            "Electricity departments never disconnect power without official prior written notice.",
        ],
        "hindi": {
            "summary_title": "बिजली बिल कनेक्शन काटने की धोखाधड़ी",
            "why_flagged": (
                "संदेश में दावा किया गया है कि बिल जमा न होने के कारण आज रात बिजली काट दी जाएगी और अधिकारी के नंबर पर संपर्क करें। "
                "बिजली विभाग कभी भी व्यक्तिगत मोबाइल नंबरों से इस तरह बिजली काटने की धमकी नहीं भेजता।"
            ),
            "recommended_actions": [
                "संदेश में दिए गए कथित बिजली अधिकारी के नंबर पर कतई कॉल न करें।",
                "अपने बिल की स्थिति की जांच केवल आधिकारिक बिजली बोर्ड पोर्टल या ऐप पर करें।",
                "इस फर्जी संदेश को नजरअंदाज करें और साइबर सेल में शिकायत दर्ज करें।",
            ],
        },
    },

    "fake_delivery_fee": {
        "summary_title": "Fake Delivery / Parcel Fee Scam Detected",
        "why_flagged": (
            "The message claims that your postal parcel or package is on hold due to an incomplete address "
            "or pending nominal delivery fee (e.g. ₹25), directing you to update details via a phishing link. "
            "Scammers use this to capture your credit/debit card credentials."
        ),
        "suspicious_factors": [
            "Claims package cannot be delivered without immediate online payment or address update",
            "Phishing URL mimicking India Post or commercial courier companies",
            "Requests payment of small nominal amounts to lower user suspicion",
        ],
        "recommended_actions": [
            "Do NOT click the tracking link or submit card/banking details.",
            "Track your package using your tracking number directly on the official courier website (e.g. indiapost.gov.in).",
            "If you did not order any item, safely ignore and delete the message.",
        ],
        "hindi": {
            "summary_title": "फर्जी पार्सल डिलीवरी शुल्क घोटाला",
            "why_flagged": (
                "संदेश में दावा किया गया है कि पता अधूरा होने या मामूली डिलीवरी शुल्क (जैसे ₹25) लंबित होने के कारण आपका पार्सल रोक दिया गया है। "
                "धोखेबाज इस लिंक के जरिए आपका कार्ड और बैंकिंग विवरण चुराने का प्रयास करते हैं।"
            ),
            "recommended_actions": [
                "ट्रैकिंग लिंक पर क्लिक न करें और न ही बैंक कार्ड विवरण दर्ज करें।",
                "पार्सल की सही जानकारी के लिए केवल आधिकारिक कूरियर वेबसाइट (जैसे indiapost.gov.in) पर ट्रैकिंग नंबर से खोजें।",
                "यदि आपने कोई पार्सल ऑर्डर नहीं किया है, तो संदेश को नजरअंदाज कर डिलीट कर दें।",
            ],
        },
    },

    "safe_transaction": {
        "summary_title": "Verified Legitimate Transaction Message",
        "why_flagged": (
            "This message contains standard transactional phrasing typical of genuine banking updates, "
            "OTP notifications, or verified merchant alerts. No deceptive links, phishing domains, or social "
            "engineering threats were detected."
        ),
        "suspicious_factors": [],
        "recommended_actions": [
            "This message appears legitimate. Always safeguard your OTP and never share it with anyone over voice calls.",
            "Verify that any transaction amounts and account numbers match your actual activity.",
        ],
        "hindi": {
            "summary_title": "सत्यापित सुरक्षित लेनदेन संदेश",
            "why_flagged": (
                "यह संदेश प्रामाणिक बैंकिंग अपडेट या आधिकारिक ओटीपी सूचना के मानकों के अनुरूप है। "
                "इसमें कोई भी संदिग्ध लिंक, धोखाधड़ी वाले शब्द या धोखे की आशंका नहीं पाई गई है।"
            ),
            "recommended_actions": [
                "संदेश सुरक्षित प्रतीत होता है। अपना ओटीपी कभी भी फोन कॉल पर किसी के साथ साझा न करें।",
                "हमेशा ध्यान दें कि लेनदेन की राशि आपके वास्तविक लेनदेन से मेल खाती हो।",
            ],
        },
    },

    "general_suspicious": {
        "summary_title": "Suspicious / Unverified Message Alert",
        "why_flagged": (
            "The message exhibits characteristics commonly associated with unsolicited promotions or unverified "
            "requests. While not explicitly proven malicious, caution is advised before clicking links or replying."
        ),
        "suspicious_factors": [
            "Unsolicited request or promotion from an unverified sender",
            "Contains unverified links or vague commercial offers",
        ],
        "recommended_actions": [
            "Do NOT click on embedded links from unverified senders.",
            "Do NOT share personal identifiers, bank details, or passwords.",
            "Verify the source through official brand channels before taking action.",
        ],
        "hindi": {
            "summary_title": "संदिग्ध / असत्यापित संदेश चेतावनी",
            "why_flagged": (
                "इस संदेश में असत्यापित प्रेषक या संदिग्ध प्रचार से जुड़े लक्षण पाए गए हैं। "
                "लिंक पर क्लिक करने या कोई व्यक्तिगत जानकारी साझा करने से पहले सावधानी बरतें।"
            ),
            "recommended_actions": [
                "अज्ञात प्रेषकों के संदेश में दिए गए लिंक पर क्लिक न करें।",
                "कोई भी व्यक्तिगत या वित्तीय जानकारी साझा न करें।",
                "कार्रवाई करने से पहले आधिकारिक माध्यमों से पुष्टि करें।",
            ],
        },
    },

    "general_malicious": {
        "summary_title": "Malicious Phishing Threat Detected",
        "why_flagged": (
            "The message has been flagged as high-risk malicious phishing. It contains deceptive indicators "
            "designed to manipulate the recipient into visiting dangerous web destinations or compromising security."
        ),
        "suspicious_factors": [
            "High-risk linguistic patterns matching known digital financial scams",
            "Presence of suspicious or blacklisted web destination",
            "Urgent social engineering pressure",
        ],
        "recommended_actions": [
            "Do NOT click any links, open attachments, or reply to this message.",
            "Do NOT share OTPs, UPI PINs, or banking credentials.",
            "Report the sender to the National Cyber Crime Helpline (1930) or cybercrime.gov.in.",
        ],
        "hindi": {
            "summary_title": "हानिकारक फ़िशिंग (Phishing) का प्रयास",
            "why_flagged": (
                "इस संदेश को उच्च-जोखिम फ़िशिंग के रूप में पहचाना गया है। इसमें उपयोगकर्ताओं को धोखा देकर "
                "हानिकारक वेबसाइटों पर ले जाने या वित्तीय सुरक्षा से समझौता कराने के संकेत मौजूद हैं।"
            ),
            "recommended_actions": [
                "किसी भी लिंक पर क्लिक न करें और न ही कोई जवाब दें।",
                "अपना ओटीपी, पिन या पासवर्ड कभी किसी के साथ साझा न करें।",
                "राष्ट्रीय साइबर अपराध हेल्पलाइन (1930) पर तुरंत रिपोर्ट करें।",
            ],
        },
    },
}


def build_deterministic_explanation(
    fraud_type: str,
    classification: str,
    risk_score: float,
    evidence_reasons: List[str] = None,
    token_attributions: Optional[List[TokenSpan]] = None,
    top_risk_tokens: Optional[List[str]] = None,
    top_safe_tokens: Optional[List[str]] = None,
) -> ExplanationResult:
    """Constructs an ExplanationResult from domain-expert deterministic templates."""
    template = DETERMINISTIC_TEMPLATES.get(fraud_type) or DETERMINISTIC_TEMPLATES.get(
        "general_malicious" if classification == "MALICIOUS" else "general_suspicious"
    )

    factors = list(template.get("suspicious_factors", []))
    if evidence_reasons:
        for r in evidence_reasons:
            if r and r not in factors:
                factors.append(r)

    hindi_data = template.get("hindi")
    hindi = None
    if hindi_data:
        hindi = HindiExplanation(
            summary_title=hindi_data["summary_title"],
            why_flagged=hindi_data["why_flagged"],
            recommended_actions=list(hindi_data.get("recommended_actions", [])),
        )

    return ExplanationResult(
        summary_title=template["summary_title"],
        fraud_type=fraud_type,
        why_flagged=template["why_flagged"],
        suspicious_factors=factors[:5],
        recommended_actions=list(template.get("recommended_actions", [])),
        token_attributions=token_attributions or [],
        top_risk_tokens=top_risk_tokens or [],
        top_safe_tokens=top_safe_tokens or [],
        hindi=hindi,
        model_used="deterministic_rule_engine_v1",
        is_ai_generated=False,
    )
