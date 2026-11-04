"""Curated seed dataset generator covering complete detection scope."""

import csv
import os
from typing import List, Dict

SEED_RECORDS: List[Dict[str, str]] = [
    # 1. Bank Impersonation & Account Suspension
    {"text": "Dear SBI User, your Netbanking account will be blocked today due to pending KYC. Click here to update: https://sbi-kyc-verify.net", "label": "1", "category": "bank_impersonation", "source_id": "DS-01"},
    {"text": "HDFC Bank Alert: Your debit card ending in 4021 has been suspended due to suspicious activity. Reactivate now at https://hdfc-reactivate.xyz", "label": "1", "category": "bank_impersonation", "source_id": "DS-01"},
    {"text": "ICICI Alert: Your account is on hold. Submit your PAN card immediately to avoid account termination: http://icici-pan-verify.com", "label": "1", "category": "bank_impersonation", "source_id": "DS-01"},
    {"text": "PNB Customer, your bank account access will be terminated within 24 hours. Verify your account at https://pnb-verify.in/auth", "label": "1", "category": "bank_impersonation", "source_id": "DS-01"},
    {"text": "Axis Bank: Your account KYC has expired. Please upload identity documents at https://axis-online-kyc.com/portal", "label": "1", "category": "bank_impersonation", "source_id": "DS-01"},
    {"text": "Dear customer, your Bank of Baroda account has been temporarily disabled. Visit http://bob-helpdesk.online to unblock.", "label": "1", "category": "bank_impersonation", "source_id": "DS-01"},
    {"text": "Canara Bank Notice: Unauthorized login detected on your mobile banking. Secure your account immediately: https://canara-secure.com", "label": "1", "category": "bank_impersonation", "source_id": "DS-01"},

    # 2. UPI Scams & Fake Payment Confirmations
    {"text": "You have received a payment request of Rs. 4,999 on PhonePe for your OLX sale. Enter your UPI PIN to accept payment.", "label": "1", "category": "upi_scam", "source_id": "DS-01"},
    {"text": "GooglePay: Cash refund of INR 2,450 is approved. Click to claim directly to your bank account: https://gpay-rewards-claim.com", "label": "1", "category": "upi_scam", "source_id": "DS-01"},
    {"text": "Paytm Alert: Your cashback reward of Rs. 1,890 has arrived! Claim immediately within 24 hrs: http://paytm-cashback-gift.top", "label": "1", "category": "upi_scam", "source_id": "DS-01"},
    {"text": "UPI Transfer failed. Amount Rs 15000 debited from sender but pending credit to you. Verify VPA: http://upi-resolution-desk.biz", "label": "1", "category": "upi_scam", "source_id": "DS-01"},
    {"text": "BHIM UPI: You received Rs 3,500 bonus cashback. Authorize by clicking http://bhim-upi-reward.xyz and entering PIN.", "label": "1", "category": "upi_scam", "source_id": "DS-01"},

    # 3. KYC Update & PAN Deactivation Threats
    {"text": "URGENT: Your SBI YONO account will be deactivated today because PAN card is not linked. Update immediately: https://sbi-pan-link.com", "label": "1", "category": "kyc_scam", "source_id": "DS-01"},
    {"text": "Dear user, your SIM card and banking services will be stopped at 9:30 PM due to unverified Aadhaar. Contact 9876543210 or visit http://e-kyc-telecom.com", "label": "1", "category": "kyc_scam", "source_id": "DS-01"},
    {"text": "Income Tax Notice: Urgent action required. Verify your PAN card details to receive income tax refund of Rs 18,750: https://it-refund-claim.org", "label": "1", "category": "kyc_scam", "source_id": "DS-01"},
    {"text": "Attention: Your Aadhaar verification is incomplete. All banking services will be suspended. Update KYC now at https://uidai-kyc-portal.club", "label": "1", "category": "kyc_scam", "source_id": "DS-01"},

    # 4. OTP & Credential Theft Attempts
    {"text": "Bank Verification Officer: We detected unauthorized transaction of Rs 45,000. Send us the 6-digit OTP you just received to cancel it immediately.", "label": "1", "category": "otp_theft", "source_id": "DS-01"},
    {"text": "HDFC Security: Do not share OTP with anyone. Our support representative is calling you to verify OTP for reversing fraudulent charge.", "label": "1", "category": "otp_theft", "source_id": "DS-01"},
    {"text": "Enter your netbanking password and OTP on our security portal http://bank-safe-verify.info to stop card compromise.", "label": "1", "category": "otp_theft", "source_id": "DS-01"},
    {"text": "Your ATM PIN needs mandatory update due to RBI safety norms. Update PIN here: https://rbi-atm-pin-safety.net", "label": "1", "category": "otp_theft", "source_id": "DS-01"},

    # 5. Phishing Links & Shortened URLs
    {"text": "Claim your complimentary Rs 500 mobile recharge bonus today! Click here before it expires: https://bit.ly/3xRechargeBonus", "label": "1", "category": "phishing_link", "source_id": "DS-01"},
    {"text": "Important notice regarding your savings account: Please review new security advisory at https://tinyurl.com/bank-security-notice", "label": "1", "category": "phishing_link", "source_id": "DS-01"},
    {"text": "Exclusive reward points worth Rs 4,200 expiring tonight. Convert points to cash at https://t.co/pointsRedeemCash", "label": "1", "category": "phishing_link", "source_id": "DS-01"},
    {"text": "Your credit score improved! Check pre-approved loan of 10 Lakhs with zero interest: https://cutt.ly/preapproved-loan-offer", "label": "1", "category": "phishing_link", "source_id": "DS-01"},

    # 6. Fake Delivery Messages
    {"text": "India Post: Your package could not be delivered due to incomplete delivery address. Update details within 12 hours: http://indiapost-redelivery.org", "label": "1", "category": "delivery_scam", "source_id": "DS-01"},
    {"text": "BlueDart Notice: Shipment #BD849204 has pending customs customs duty of Rs 25. Pay online to release delivery: https://bluedart-customs-pay.com", "label": "1", "category": "delivery_scam", "source_id": "DS-01"},
    {"text": "Amazon Courier: Delivery boy tried to reach you for parcel #4082. Please confirm your delivery address here: http://amazon-courier-update.top", "label": "1", "category": "delivery_scam", "source_id": "DS-01"},
    {"text": "Delhivery: Your package is returned to warehouse. Reschedule delivery date immediately at https://delhivery-package-track.info", "label": "1", "category": "delivery_scam", "source_id": "DS-01"},

    # 7. Fake Job Offers & Daily Payouts
    {"text": "Amazon Hiring: Part-time work from home opportunity! Earn Rs 2,500 to 5,000 daily by rating products. Contact manager on WhatsApp: https://wa.me/919876543210", "label": "1", "category": "job_scam", "source_id": "DS-01"},
    {"text": "YouTube Video Reviewer Job: Earn Rs 3,000 per day by simply liking videos! Zero investment. Join official Telegram group: https://t.me/daily_task_earning", "label": "1", "category": "job_scam", "source_id": "DS-01"},
    {"text": "Congratulations! Your resume was shortlisted for Data Entry position at MNC. Daily payout Rs 2,000. WhatsApp HR at 9811223344.", "label": "1", "category": "job_scam", "source_id": "DS-01"},

    # 8. Lottery & Prize Scams
    {"text": "Dear Winner, you have won Rs 25,00,000 in KBC Jio Lucky Draw 2026! Contact Rana Pratap Singh on WhatsApp 9822334455 to claim your prize cheque.", "label": "1", "category": "lottery_scam", "source_id": "DS-01"},
    {"text": "Congratulations! Your mobile number won 1st prize of brand new Tata Nexon SUV in Diwali mega draw. Claim at http://tata-mega-winner.com", "label": "1", "category": "lottery_scam", "source_id": "DS-01"},
    {"text": "International Lottery Council: Your email won 500,000 GBP. Send your banking details and passport copy to lottery@claims-dept.com to process.", "label": "1", "category": "lottery_scam", "source_id": "DS-01"},

    # 9. Government Benefit Impersonation
    {"text": "PM Kisan Yojana: 17th installment of Rs 2,000 has been transferred. Check beneficiary status and verify biometric: https://pmkisan-gov-verify.com", "label": "1", "category": "gov_benefit_scam", "source_id": "DS-01"},
    {"text": "Ministry of Finance: Government has approved unemployment relief grant of Rs 5,000 to your bank account. Apply here: https://gov-relief-subsidy.in", "label": "1", "category": "gov_benefit_scam", "source_id": "DS-01"},
    {"text": "LPG Subsidy Department: Your cylinder subsidy of Rs 450 is on hold. Update bank details at http://lpg-subsidy-portal.xyz", "label": "1", "category": "gov_benefit_scam", "source_id": "DS-01"},

    # 10. Electricity Bill & Utility Scams
    {"text": "Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM from electricity office because previous month bill was not updated. Call electricity officer immediately: 9876501234.", "label": "1", "category": "utility_scam", "source_id": "DS-01"},
    {"text": "URGENT ELECTRICITY NOTICE: Power disconnection order issued for your meter. Pay bill immediately or contact chief engineer at 9123456789.", "label": "1", "category": "utility_scam", "source_id": "DS-01"},
    {"text": "Gas pipeline supply disconnection notice: Your piped gas connection will be disconnected within 2 hours. Pay bill via http://citygas-billpay.biz", "label": "1", "category": "utility_scam", "source_id": "DS-01"},

    # 11. Investment & Loan Scams
    {"text": "Instant Personal Loan approved of Rs 5,00,000 with 0% interest and no CIBIL check! Disbursed in 5 minutes: https://instant-cash-loan-app.club", "label": "1", "category": "loan_scam", "source_id": "DS-01"},
    {"text": "Crypto Wealth Club: Invest Rs 10,000 today and receive Rs 35,000 guaranteed daily profit. Join our VIP channel: http://crypto-profit-daily.xyz", "label": "1", "category": "loan_scam", "source_id": "DS-01"},
    {"text": "Stock market insider tips: 100% guaranteed jackpot calls with 500% returns in 3 days. Join SEBI registered advisory on Telegram https://t.me/jackpot_stocks", "label": "1", "category": "loan_scam", "source_id": "DS-01"},

    # 12. Fake Customer Support & Malware Hosting
    {"text": "Google Pay support: For any refund issues or transaction failure, call our 24x7 customer support toll free executive at 9870001122.", "label": "1", "category": "fake_support", "source_id": "DS-01"},
    {"text": "Download the new upgraded SBI Mobile Banking APK for seamless transactions: http://sbi-security-apk.download/sbi_v4.apk", "label": "1", "category": "malware_url", "source_id": "DS-01"},

    # -----------------------------------------------------------------------
    # LEGITIMATE MESSAGES (Label: 0)
    # -----------------------------------------------------------------------

    # 13. Legitimate Bank Transactional Alerts (Debits, Credits, Statements)
    {"text": "Rs. 1,450.00 debited from A/C XX4921 on 04-Nov-26 at SWIGGY BANGALORE. Avl Bal: Rs. 48,210.50. Call 1800112211 if not done by you - SBI.", "label": "0", "category": "transactional_clean", "source_id": "DS-01"},
    {"text": "Your A/C 9081 is credited with INR 75,000.00 on 31-Oct-26 by NEFT-SALARY OCTOBER. Clear balance: INR 1,12,450.00 - HDFC Bank.", "label": "0", "category": "transactional_clean", "source_id": "DS-01"},
    {"text": "Dear Customer, INR 450.00 spent on your ICICI Bank Credit Card XX2041 at SHELL PETROL on 03-Nov-26. Available limit: INR 1,45,000.00.", "label": "0", "category": "transactional_clean", "source_id": "DS-01"},
    {"text": "UPI Transaction Alert: Rs 120.00 paid to Chai Point via Google Pay from Axis Bank A/C XX3819 on 04-Nov-26. UPI Ref 4309182910.", "label": "0", "category": "transactional_clean", "source_id": "DS-01"},
    {"text": "Bill for your Airtel Broadband 08041234567 is Rs 943.00. Due date is 15-Nov-26. Thank you for choosing Airtel.", "label": "0", "category": "transactional_clean", "source_id": "DS-01"},
    {"text": "Tata Power: Bill for Consumer No 019283746 is Rs 1,840.00 due on 12-Nov-26. Pay online at tatapower.com or via authorized centers.", "label": "0", "category": "transactional_clean", "source_id": "DS-01"},
    {"text": "Salary credit: Your account ending in 8192 has been credited with salary of Rs 62,500.00 on 01-Nov-26. Current balance: Rs 78,200.00 - PNB.", "label": "0", "category": "transactional_clean", "source_id": "DS-01"},
    {"text": "Mutual fund SIP of Rs 5,000.00 in Parag Parikh Flexi Cap Fund successfully processed on 02-Nov-26. Nav: 82.41.", "label": "0", "category": "transactional_clean", "source_id": "DS-01"},
    {"text": "IndiGo booking confirmed! PNR: 6E-9021. Flight 6E-241 from DEL to BLR on 10-Nov-26 departing 14:15. Web check-in opens 48 hours prior.", "label": "0", "category": "transactional_clean", "source_id": "DS-01"},
    {"text": "Your Uber ride of Rs 340.00 is complete. Thank you for riding with Uber. View ride receipt in your app.", "label": "0", "category": "transactional_clean", "source_id": "DS-01"},

    # 14. Legitimate Benign OTP Messages (No URLs, No Threats)
    {"text": "729401 is your Amazon login verification code. It is valid for 10 minutes. Do not share this code with anyone.", "label": "0", "category": "otp_clean", "source_id": "DS-01"},
    {"text": "581902 is your OTP to complete Swiggy order payment of Rs 480.00. Valid for 5 mins. Swiggy never asks for OTP.", "label": "0", "category": "otp_clean", "source_id": "DS-01"},
    {"text": "Google verification code: 394820. Do not share with anyone.", "label": "0", "category": "otp_clean", "source_id": "DS-01"},
    {"text": "Your one-time password for Zomato login is 6102. Valid for 10 minutes.", "label": "0", "category": "otp_clean", "source_id": "DS-01"},
    {"text": "Microsoft security code: 849201. Use this to verify identity.", "label": "0", "category": "otp_clean", "source_id": "DS-01"},
    {"text": "829471 is the OTP for registering Aadhaar on DigiLocker. Do not disclose.", "label": "0", "category": "otp_clean", "source_id": "DS-01"},

    # 15. Legitimate Conversational & Personal Messages
    {"text": "Hey, are we still meeting for lunch at 1 PM today? Let me know where you want to go.", "label": "0", "category": "conversational_clean", "source_id": "DS-01"},
    {"text": "Hi Mom, reached office safely. Will call you during evening tea break.", "label": "0", "category": "conversational_clean", "source_id": "DS-01"},
    {"text": "Can you please send me the presentation slides before the 3 PM team meeting?", "label": "0", "category": "conversational_clean", "source_id": "DS-01"},
    {"text": "Happy Birthday Rahul! Wishing you wonderful year ahead filled with happiness and success.", "label": "0", "category": "conversational_clean", "source_id": "DS-01"},
    {"text": "Please bring bread and milk on your way back home from office.", "label": "0", "category": "conversational_clean", "source_id": "DS-01"},
    {"text": "The doctor appointment is rescheduled to tomorrow morning at 10:30 AM.", "label": "0", "category": "conversational_clean", "source_id": "DS-01"},
    {"text": "Train is running on time. Expected arrival at New Delhi station is 18:45.", "label": "0", "category": "conversational_clean", "source_id": "DS-01"},
    {"text": "Thanks for helping with the assignment yesterday, really appreciate it!", "label": "0", "category": "conversational_clean", "source_id": "DS-01"},
    {"text": "Let me know when you reach Bangalore, will arrange the cab for you.", "label": "0", "category": "conversational_clean", "source_id": "DS-01"},
    {"text": "Great match today! Let us play tennis again this Saturday morning.", "label": "0", "category": "conversational_clean", "source_id": "DS-01"},

    # 16. Legitimate Commercial & Promotional (Not Scam)
    {"text": "Dominos Pizza: Flat 50% OFF on all pizzas today! Use coupon code FEAST50 on Dominos App. T&C apply.", "label": "0", "category": "promotional_clean", "source_id": "DS-01"},
    {"text": "Myntra End of Reason Sale starts midnight! Wishlist your favorite fashion brands now. Download Myntra app.", "label": "0", "category": "promotional_clean", "source_id": "DS-01"},
    {"text": "BookMyShow: Tickets for Coldplay India Tour are now live on BookMyShow. Reserve your seats today.", "label": "0", "category": "promotional_clean", "source_id": "DS-01"},
    {"text": "Cult.fit: Renew your annual gym membership today and get 2 months free extension. Offer ends Sunday.", "label": "0", "category": "promotional_clean", "source_id": "DS-01"},
]


def generate_curated_csv(filepath: str) -> None:
    """Generates the curated SMS dataset CSV file with complete metadata."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    fieldnames = ["text", "label", "category", "source_id"]

    with open(filepath, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for rec in SEED_RECORDS:
            writer.writerow(rec)


if __name__ == "__main__":
    target = os.path.join(os.path.dirname(__file__), "sms_corpus.csv")
    generate_curated_csv(target)
    print(f"Generated {len(SEED_RECORDS)} curated records at: {target}")
