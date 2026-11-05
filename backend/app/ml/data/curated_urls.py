"""Curated seed dataset generator for URL phishing and benign classification."""

import csv
import os
from typing import List, Dict

SEED_URLS: List[Dict[str, str]] = [
    # -----------------------------------------------------------------------
    # MALICIOUS & PHISHING URLS (Label: 1)
    # -----------------------------------------------------------------------
    # 1. Bank Impersonation & Phishing Portals
    {"url": "http://sbi-kyc-verify.net/portal/login.php", "label": "1", "category": "bank_phishing", "source_id": "DS-03"},
    {"url": "https://hdfc-reactivate.xyz/netbanking/auth", "label": "1", "category": "bank_phishing", "source_id": "DS-03"},
    {"url": "http://icici-pan-verify.com/security/update-details", "label": "1", "category": "bank_phishing", "source_id": "DS-03"},
    {"url": "https://pnb-verify.in/auth/login", "label": "1", "category": "bank_phishing", "source_id": "DS-03"},
    {"url": "https://axis-online-kyc.com/portal/document-upload", "label": "1", "category": "bank_phishing", "source_id": "DS-03"},
    {"url": "http://bob-helpdesk.online/reactivate-account", "label": "1", "category": "bank_phishing", "source_id": "DS-03"},
    {"url": "https://canara-secure.com/auth/ebanking", "label": "1", "category": "bank_phishing", "source_id": "DS-03"},
    {"url": "https://bank-safe-verify.info/netbanking/password-reset", "label": "1", "category": "bank_phishing", "source_id": "DS-03"},
    {"url": "http://secure-banking-alert.club/signin.aspx", "label": "1", "category": "bank_phishing", "source_id": "DS-03"},
    {"url": "https://sbi-pan-link.com/kyc/update", "label": "1", "category": "bank_phishing", "source_id": "DS-03"},

    # 2. UPI & Financial Fraud Lures
    {"url": "https://gpay-rewards-claim.com/claim-vpa", "label": "1", "category": "upi_scam", "source_id": "DS-03"},
    {"url": "http://paytm-cashback-gift.top/redeem", "label": "1", "category": "upi_scam", "source_id": "DS-03"},
    {"url": "http://upi-resolution-desk.biz/refund/verify", "label": "1", "category": "upi_scam", "source_id": "DS-03"},
    {"url": "http://bhim-upi-reward.xyz/authorize-cashback", "label": "1", "category": "upi_scam", "source_id": "DS-03"},
    {"url": "http://instant-cash-loan-app.club/apply/kyc", "label": "1", "category": "loan_scam", "source_id": "DS-03"},
    {"url": "http://crypto-profit-daily.xyz/invest", "label": "1", "category": "loan_scam", "source_id": "DS-03"},

    # 3. Utility & Delivery Scams
    {"url": "http://indiapost-redelivery.org/track/address-update", "label": "1", "category": "delivery_scam", "source_id": "DS-03"},
    {"url": "https://bluedart-customs-pay.com/shipment/pay-fee", "label": "1", "category": "delivery_scam", "source_id": "DS-03"},
    {"url": "http://amazon-courier-update.top/order-failed", "label": "1", "category": "delivery_scam", "source_id": "DS-03"},
    {"url": "https://delhivery-package-track.info/reschedule", "label": "1", "category": "delivery_scam", "source_id": "DS-03"},
    {"url": "http://citygas-billpay.biz/officer-contact", "label": "1", "category": "utility_scam", "source_id": "DS-03"},
    {"url": "http://electricity-bill-disconnection.xyz/pay", "label": "1", "category": "utility_scam", "source_id": "DS-03"},

    # 4. Raw IP, Shorteners, Punycode, & DGA
    {"url": "http://45.33.32.156/bank/login.php", "label": "1", "category": "ip_host", "source_id": "DS-04"},
    {"url": "http://185.220.101.5/steal/credentials", "label": "1", "category": "ip_host", "source_id": "DS-04"},
    {"url": "http://192.168.1.1:8080/admin", "label": "1", "category": "ip_host", "source_id": "DS-04"},
    {"url": "https://bit.ly/3xRechargeBonus", "label": "1", "category": "shortened_phish", "source_id": "DS-03"},
    {"url": "https://tinyurl.com/sbi-verify-kyc", "label": "1", "category": "shortened_phish", "source_id": "DS-03"},
    {"url": "https://t.co/pointsRedeemCash", "label": "1", "category": "shortened_phish", "source_id": "DS-03"},
    {"url": "https://cutt.ly/preapproved-loan-offer", "label": "1", "category": "shortened_phish", "source_id": "DS-03"},
    {"url": "https://xn--sbi-9o0a.com/portal/login", "label": "1", "category": "punycode_homograph", "source_id": "DS-03"},
    {"url": "https://xn--hdfc-4oa.net/ebanking", "label": "1", "category": "punycode_homograph", "source_id": "DS-03"},
    {"url": "http://qwx9102ksjd81920z.xyz/payload.exe", "label": "1", "category": "dga_malware", "source_id": "DS-04"},
    {"url": "http://sbi-security-apk.download/sbi_v4.apk", "label": "1", "category": "malware_url", "source_id": "DS-04"},
    {"url": "http://tata-mega-winner.com/claim-prize", "label": "1", "category": "lottery_scam", "source_id": "DS-03"},
    {"url": "https://uidai-kyc-portal.club/biometric-verify", "label": "1", "category": "kyc_scam", "source_id": "DS-03"},
    {"url": "https://it-refund-claim.org/pan-verification", "label": "1", "category": "kyc_scam", "source_id": "DS-03"},

    # -----------------------------------------------------------------------
    # BENIGN & LEGITIMATE URLS (Label: 0)
    # -----------------------------------------------------------------------
    # 5. Trusted Banking & Financial Services
    {"url": "https://www.onlinesbi.sbi", "label": "0", "category": "banking_benign", "source_id": "DS-05"},
    {"url": "https://www.onlinesbi.sbi/sbijava/osbi_retail_banking.html", "label": "0", "category": "banking_benign", "source_id": "DS-05"},
    {"url": "https://www.hdfcbank.com", "label": "0", "category": "banking_benign", "source_id": "DS-05"},
    {"url": "https://netbanking.hdfcbank.com/netbanking", "label": "0", "category": "banking_benign", "source_id": "DS-05"},
    {"url": "https://www.icicibank.com", "label": "0", "category": "banking_benign", "source_id": "DS-05"},
    {"url": "https://infinity.icicibank.com/corp/AuthenticationController", "label": "0", "category": "banking_benign", "source_id": "DS-05"},
    {"url": "https://www.axisbank.com", "label": "0", "category": "banking_benign", "source_id": "DS-05"},
    {"url": "https://www.pnbindia.in", "label": "0", "category": "banking_benign", "source_id": "DS-05"},
    {"url": "https://www.bankofbaroda.in", "label": "0", "category": "banking_benign", "source_id": "DS-05"},
    {"url": "https://rbi.org.in", "label": "0", "category": "banking_benign", "source_id": "DS-05"},
    {"url": "https://www.npci.org.in", "label": "0", "category": "banking_benign", "source_id": "DS-05"},

    # 6. Trusted Government & Public Services
    {"url": "https://uidai.gov.in", "label": "0", "category": "gov_benign", "source_id": "DS-05"},
    {"url": "https://myaadhaar.uidai.gov.in", "label": "0", "category": "gov_benign", "source_id": "DS-05"},
    {"url": "https://www.incometax.gov.in/iec/foportal", "label": "0", "category": "gov_benign", "source_id": "DS-05"},
    {"url": "https://www.indiapost.gov.in/vas/pages/indiaposthome.aspx", "label": "0", "category": "gov_benign", "source_id": "DS-05"},
    {"url": "https://pmkisan.gov.in", "label": "0", "category": "gov_benign", "source_id": "DS-05"},
    {"url": "https://digilocker.gov.in", "label": "0", "category": "gov_benign", "source_id": "DS-05"},
    {"url": "https://www.irctc.co.in/nget/train-search", "label": "0", "category": "gov_benign", "source_id": "DS-05"},

    # 7. Trusted Commerce, Delivery & Utility Portals
    {"url": "https://www.amazon.in", "label": "0", "category": "commerce_benign", "source_id": "DS-05"},
    {"url": "https://www.amazon.in/gp/your-account/order-history", "label": "0", "category": "commerce_benign", "source_id": "DS-05"},
    {"url": "https://www.flipkart.com", "label": "0", "category": "commerce_benign", "source_id": "DS-05"},
    {"url": "https://www.swiggy.com", "label": "0", "category": "commerce_benign", "source_id": "DS-05"},
    {"url": "https://www.zomato.com/bangalore", "label": "0", "category": "commerce_benign", "source_id": "DS-05"},
    {"url": "https://www.tatapower.com", "label": "0", "category": "commerce_benign", "source_id": "DS-05"},
    {"url": "https://www.airtel.in", "label": "0", "category": "commerce_benign", "source_id": "DS-05"},
    {"url": "https://www.bluedart.com", "label": "0", "category": "commerce_benign", "source_id": "DS-05"},

    # 8. Trusted Global Internet Services
    {"url": "https://www.google.com", "label": "0", "category": "global_benign", "source_id": "DS-05"},
    {"url": "https://www.microsoft.com", "label": "0", "category": "global_benign", "source_id": "DS-05"},
    {"url": "https://github.com/torvalds/linux", "label": "0", "category": "global_benign", "source_id": "DS-05"},
    {"url": "https://en.wikipedia.org/wiki/Phishing", "label": "0", "category": "global_benign", "source_id": "DS-05"},
    {"url": "https://www.apple.com", "label": "0", "category": "global_benign", "source_id": "DS-05"},
    {"url": "https://aws.amazon.com/security", "label": "0", "category": "global_benign", "source_id": "DS-05"},
    {"url": "https://cloudflare.com", "label": "0", "category": "global_benign", "source_id": "DS-05"},
    {"url": "https://open-source.org", "label": "0", "category": "global_benign", "source_id": "DS-05"},
    {"url": "https://linux-foundation.org", "label": "0", "category": "global_benign", "source_id": "DS-05"},
    {"url": "https://www.mercedes-benz.com", "label": "0", "category": "global_benign", "source_id": "DS-05"},
    {"url": "https://www.coca-cola.com", "label": "0", "category": "global_benign", "source_id": "DS-05"},
    {"url": "https://www.t-mobile.com", "label": "0", "category": "global_benign", "source_id": "DS-05"},
    {"url": "https://lets-encrypt.org", "label": "0", "category": "global_benign", "source_id": "DS-05"},
    {"url": "https://apache-airflow.org", "label": "0", "category": "global_benign", "source_id": "DS-05"},
    {"url": "https://untracked-blog-site.org", "label": "0", "category": "global_benign", "source_id": "DS-05"},
    {"url": "https://my-personal-blog.org", "label": "0", "category": "global_benign", "source_id": "DS-05"},
]


def generate_curated_urls_csv(filepath: str) -> None:
    """Generates the curated URL dataset CSV file."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    fieldnames = ["url", "label", "category", "source_id"]

    with open(filepath, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for rec in SEED_URLS:
            writer.writerow(rec)


if __name__ == "__main__":
    target = os.path.join(os.path.dirname(__file__), "url_corpus.csv")
    generate_curated_urls_csv(target)
    print(f"Generated {len(SEED_URLS)} curated URL records at: {target}")
