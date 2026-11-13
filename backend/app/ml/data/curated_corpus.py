"""Curated seed dataset generator covering complete 12 fraud detection scope + clean messages."""

import csv
import os
from typing import List, Dict

SEED_RECORDS: List[Dict[str, str]] = [
    # 1. Fake Payment Confirmation Scam
    {"text": "Rs 45,000.00 credited to your account from Amit Kumar via IMPS. Click http://bank-credit-confirm.xyz to release funds.", "label": "1", "category": "fake_payment_confirmation", "source_id": "DS-01"},
    {"text": "Payment Successful: You received Rs 12,500 on PhonePe from buyer. Confirm transaction receipt at http://phonepe-receive-ack.cc", "label": "1", "category": "fake_payment_confirmation", "source_id": "DS-01"},
    {"text": "A/C credited with Rs 28,000 transferred by Ramesh. Verify your identity at http://pay-confirmation-gateway.top to claim money.", "label": "1", "category": "fake_payment_confirmation", "source_id": "DS-01"},
    {"text": "SBI Alert: Amount of Rs 85,000 sent to your a/c. Complete authorization at http://sbi-imps-receiver.info to credit to balance.", "label": "1", "category": "fake_payment_confirmation", "source_id": "DS-01"},
    {"text": "GooglePay: You received Rs 15,000 from Rohit Sharma for laptop purchase. Click to accept payment http://gpay-settle-claim.online", "label": "1", "category": "fake_payment_confirmation", "source_id": "DS-01"},
    {"text": "Money transferred! Rs 9,400 credited to your UPI ID. Settle payment immediately at http://upi-merchant-credit.top", "label": "1", "category": "fake_payment_confirmation", "source_id": "DS-01"},

    # 2. Fake UPI Collect Request Scam
    {"text": "You have received a payment request of Rs. 4,999 on PhonePe for your OLX sale. Enter your UPI PIN to accept payment.", "label": "1", "category": "fake_upi_collect_request", "source_id": "DS-01"},
    {"text": "Merchant collect request of Rs 7,500 received. Click approve in GPay and enter UPI PIN to receive money in your bank.", "label": "1", "category": "fake_upi_collect_request", "source_id": "DS-01"},
    {"text": "Payment collect request of Rs 2,000 pending. Approve request to credit amount to your Paytm wallet instantly.", "label": "1", "category": "fake_upi_collect_request", "source_id": "DS-01"},
    {"text": "BHIM UPI: Collect request received for Rs 14,000. Enter secret UPI PIN to receive money from client.", "label": "1", "category": "fake_upi_collect_request", "source_id": "DS-01"},
    {"text": "Incoming funds pending: Approve collect request from Sharma Traders to deposit Rs 6,800 to account.", "label": "1", "category": "fake_upi_collect_request", "source_id": "DS-01"},
    {"text": "Click approve on the UPI request to accept Rs 3,200 refund. Enter PIN to confirm receipt.", "label": "1", "category": "fake_upi_collect_request", "source_id": "DS-01"},

    # 3. QR-Code Payment Scam
    {"text": "Scan this QR code using PhonePe or GPay to claim your cashback refund of Rs 1,500 immediately.", "label": "1", "category": "qr_code_scam", "source_id": "DS-01"},
    {"text": "Dear customer, scan the attached QR code to receive your advance token money of Rs 5,000 for sofa.", "label": "1", "category": "qr_code_scam", "source_id": "DS-01"},
    {"text": "Refund approved: Open Google Pay, scan QR code and enter UPI PIN to receive Rs 2,400 refund.", "label": "1", "category": "qr_code_scam", "source_id": "DS-01"},
    {"text": "Paytm Prize: Scan this dynamic QR code to deposit Rs 10,000 festive gift into your account.", "label": "1", "category": "qr_code_scam", "source_id": "DS-01"},
    {"text": "OLX buyer sent you a payment QR code. Scan QR code in your UPI app to receive Rs 8,500.", "label": "1", "category": "qr_code_scam", "source_id": "DS-01"},
    {"text": "Scan QR to claim reimbursement of Rs 3,900 from airline ticketing department.", "label": "1", "category": "qr_code_scam", "source_id": "DS-01"},

    # 4. Fake Refund Scam
    {"text": "Your previous transaction failed. Claim refund of Rs 1,499 now by approving the reversal request: http://paytm-refund-desk.cc", "label": "1", "category": "fake_refund_scam", "source_id": "DS-01"},
    {"text": "IRCTC Ticket Cancellation Refund of Rs 3,850 is ready. Click link to deposit into bank: http://irctc-refund-portal.net", "label": "1", "category": "fake_refund_scam", "source_id": "DS-01"},
    {"text": "Swiggy order cancellation refund pending. Submit VPA to process instant refund: http://swiggy-refund-help.xyz", "label": "1", "category": "fake_refund_scam", "source_id": "DS-01"},
    {"text": "Amazon Pay: Your double debit refund of Rs 5,200 is approved. Click to authorize credit: http://amazon-refund-settlement.biz", "label": "1", "category": "fake_refund_scam", "source_id": "DS-01"},
    {"text": "Flipkart Refund Notice: Tap http://flipkart-money-reversal.top and enter OTP to complete Rs 7,999 refund.", "label": "1", "category": "fake_refund_scam", "source_id": "DS-01"},
    {"text": "Electricity extra charge refund of Rs 1,200 available. Click here to claim refund: http://discom-refund-online.org", "label": "1", "category": "fake_refund_scam", "source_id": "DS-01"},

    # 5. Duplicate Payment Scam
    {"text": "Earlier payment of Rs 1,200 failed due to network timeout. Please pay again immediately to complete order: http://merchant-retry-pay.cc", "label": "1", "category": "duplicate_payment_scam", "source_id": "DS-01"},
    {"text": "Your flight booking transaction timed out. Pay again within 15 minutes to avoid seat cancellation: http://travel-retry-pay.xyz", "label": "1", "category": "duplicate_payment_scam", "source_id": "DS-01"},
    {"text": "First payment of Rs 4,500 was rejected by server. Retry payment immediately through this link: http://bill-pay-gateway.top", "label": "1", "category": "duplicate_payment_scam", "source_id": "DS-01"},
    {"text": "Payment incomplete: Transaction #9482 did not clear. Re-submit payment of Rs 2,800 to prevent order cancellation.", "label": "1", "category": "duplicate_payment_scam", "source_id": "DS-01"},
    {"text": "UPI payment timed out at merchant. Click here to repay Rs 1,950: http://fast-upi-retry.biz", "label": "1", "category": "duplicate_payment_scam", "source_id": "DS-01"},

    # 6. Fake Bank KYC Update SMS
    {"text": "Dear SBI User, your Netbanking account will be blocked today due to pending KYC. Click here to update: https://sbi-kyc-verify.net", "label": "1", "category": "fake_kyc_update", "source_id": "DS-01"},
    {"text": "URGENT: Your SBI YONO account will be deactivated today because PAN card is not linked. Update immediately: https://sbi-pan-link.com", "label": "1", "category": "fake_kyc_update", "source_id": "DS-01"},
    {"text": "Axis Bank: Your account KYC has expired. Please upload identity documents at https://axis-online-kyc.com/portal", "label": "1", "category": "fake_kyc_update", "source_id": "DS-01"},
    {"text": "HDFC Alert: Your NetBanking KYC verification is pending. Submit Aadhaar and PAN at http://hdfc-kyc-portal.xyz", "label": "1", "category": "fake_kyc_update", "source_id": "DS-01"},
    {"text": "Dear customer, your Bank of Baroda KYC is incomplete. Visit http://bob-helpdesk.online to submit documents immediately.", "label": "1", "category": "fake_kyc_update", "source_id": "DS-01"},
    {"text": "PNB Notice: Mandatory KYC update required by RBI guidelines. Click to update PAN: http://pnb-online-kyc.top", "label": "1", "category": "fake_kyc_update", "source_id": "DS-01"},
    {"text": "Attention: Your Aadhaar verification is incomplete. All banking services will be suspended. Update KYC now at https://uidai-kyc-portal.club", "label": "1", "category": "fake_kyc_update", "source_id": "DS-01"},

    # 7. Bank Account Suspension Scam
    {"text": "HDFC Bank Alert: Your debit card ending in 4021 has been suspended due to suspicious activity. Reactivate now at https://hdfc-reactivate.xyz", "label": "1", "category": "bank_suspension_scam", "source_id": "DS-01"},
    {"text": "ICICI Alert: Your account is on hold. Submit your PAN card immediately to avoid account termination: http://icici-pan-verify.com", "label": "1", "category": "bank_suspension_scam", "source_id": "DS-01"},
    {"text": "PNB Customer, your bank account access will be terminated within 24 hours. Verify your account at https://pnb-verify.in/auth", "label": "1", "category": "bank_suspension_scam", "source_id": "DS-01"},
    {"text": "Canara Bank Notice: Unauthorized login detected on your mobile banking. Secure your account immediately: https://canara-secure.com", "label": "1", "category": "bank_suspension_scam", "source_id": "DS-01"},
    {"text": "Kotak Alert: Account 9482 will be deactivated within 12 hours due to irregular activities. Login to restore: http://kotak-restore-login.net", "label": "1", "category": "bank_suspension_scam", "source_id": "DS-01"},
    {"text": "Your debit card has been permanently blocked. Contact helpline immediately or unlock online: http://bank-card-unlock.info", "label": "1", "category": "bank_suspension_scam", "source_id": "DS-01"},

    # 8. Fake Customer Care / Remote Access Scam
    {"text": "Paytm customer care helpline: 9876543210. Download AnyDesk to resolve pending refund immediately.", "label": "1", "category": "fake_customer_care", "source_id": "DS-01"},
    {"text": "Google Pay support: For failed transactions, call our 24x7 customer support executive on 9870001122 and install QuickSupport.", "label": "1", "category": "fake_customer_care", "source_id": "DS-01"},
    {"text": "PhonePe Helpdesk: Call 9123456789. Install TeamViewer app to get your money back in 5 minutes.", "label": "1", "category": "fake_customer_care", "source_id": "DS-01"},
    {"text": "Bank Verification Officer: We detected unauthorized charge. Send us the 6-digit OTP you just received to reverse it.", "label": "1", "category": "fake_customer_care", "source_id": "DS-01"},
    {"text": "SBI Customer Care Officer calling to cancel insurance deduction. Download RustDesk to verify phone.", "label": "1", "category": "fake_customer_care", "source_id": "DS-01"},
    {"text": "Toll free support executive: 8899001122. Share screen via AnyDesk to verify payment reversal.", "label": "1", "category": "fake_customer_care", "source_id": "DS-01"},

    # 9. Cashback & Reward Scam
    {"text": "Congratulations! You won Rs 10,000 cashback reward from Google Pay. Claim prize here: http://gpay-rewards-claim.com", "label": "1", "category": "cashback_reward_scam", "source_id": "DS-01"},
    {"text": "Paytm Alert: Your cashback reward of Rs. 1,890 has arrived! Claim immediately within 24 hrs: http://paytm-cashback-gift.top", "label": "1", "category": "cashback_reward_scam", "source_id": "DS-01"},
    {"text": "BHIM UPI: You received Rs 3,500 bonus cashback. Authorize by clicking http://bhim-upi-reward.xyz and entering PIN.", "label": "1", "category": "cashback_reward_scam", "source_id": "DS-01"},
    {"text": "Dear Winner, you have won Rs 25,00,000 in KBC Jio Lucky Draw 2026! Contact Rana Pratap Singh on WhatsApp 9822334455.", "label": "1", "category": "cashback_reward_scam", "source_id": "DS-01"},
    {"text": "Diwali Mega Lucky Draw: Your mobile number won 1st prize Tata Nexon SUV. Click to claim: http://tata-mega-winner.com", "label": "1", "category": "cashback_reward_scam", "source_id": "DS-01"},
    {"text": "Spin and win reward! You won Samsung Galaxy S25 Ultra. Pay processing fee of Rs 499 at http://prize-claim-now.xyz", "label": "1", "category": "cashback_reward_scam", "source_id": "DS-01"},

    # 10. SIM Card Disconnection Scam
    {"text": "Dear customer, your SIM card will be deactivated tonight due to missing e-KYC documents. Call executive 9876543210.", "label": "1", "category": "sim_blocking_scam", "source_id": "DS-01"},
    {"text": "Airtel Notice: Your SIM card services will be stopped at 9:30 PM due to unverified Aadhaar. Contact 9123456780 immediately.", "label": "1", "category": "sim_blocking_scam", "source_id": "DS-01"},
    {"text": "Jio e-KYC pending: Your outgoing and incoming calls will be blocked in 2 hours. Update docs at http://jio-ekyc-verification.com", "label": "1", "category": "sim_blocking_scam", "source_id": "DS-01"},
    {"text": "Vodafone Idea Alert: Upload your identity card to prevent permanent SIM disconnection: http://vi-sim-kyc.top", "label": "1", "category": "sim_blocking_scam", "source_id": "DS-01"},
    {"text": "Telecom Regulatory Authority notice: Your mobile number is flagged for immediate deactivation. Call officer now.", "label": "1", "category": "sim_blocking_scam", "source_id": "DS-01"},

    # 11. Electricity Bill Disconnection Scam
    {"text": "Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM from electricity office because previous month bill was not updated. Call electricity officer immediately: 9876501234.", "label": "1", "category": "electricity_disconnection_scam", "source_id": "DS-01"},
    {"text": "URGENT ELECTRICITY NOTICE: Power disconnection order issued for your meter. Pay bill immediately or contact chief engineer at 9123456789.", "label": "1", "category": "electricity_disconnection_scam", "source_id": "DS-01"},
    {"text": "Electric supply will be disconnected at 8:30 PM tonight due to unpaid bill. Pay via link http://bijli-bill-payment.net or call SDPO.", "label": "1", "category": "electricity_disconnection_scam", "source_id": "DS-01"},
    {"text": "Notice from state electricity board: Power cut tonight due to pending arrears of Rs 3,450. Contact officer 9811223344.", "label": "1", "category": "electricity_disconnection_scam", "source_id": "DS-01"},
    {"text": "Gas pipeline supply disconnection notice: Your piped gas connection will be disconnected within 2 hours. Pay bill via http://citygas-billpay.biz", "label": "1", "category": "electricity_disconnection_scam", "source_id": "DS-01"},

    # 12. Fake Delivery / Courier Fee Scam
    {"text": "India Post: Your package could not be delivered due to incomplete delivery address. Update details within 12 hours: http://indiapost-redelivery.org", "label": "1", "category": "fake_delivery_fee", "source_id": "DS-01"},
    {"text": "BlueDart Notice: Shipment #BD849204 has pending customs customs duty of Rs 25. Pay online to release delivery: https://bluedart-customs-pay.com", "label": "1", "category": "fake_delivery_fee", "source_id": "DS-01"},
    {"text": "Amazon Courier: Delivery boy tried to reach you for parcel #4082. Please confirm your delivery address here: http://amazon-courier-update.top", "label": "1", "category": "fake_delivery_fee", "source_id": "DS-01"},
    {"text": "Delhivery: Your package is returned to warehouse. Pay Rs 48 redelivery fee immediately at https://delhivery-package-track.info", "label": "1", "category": "fake_delivery_fee", "source_id": "DS-01"},
    {"text": "SpeedPost parcel is on hold at sorting facility. Update street address and postal fee: http://speedpost-tracking-india.com", "label": "1", "category": "fake_delivery_fee", "source_id": "DS-01"},
    {"text": "DTDC Courier: Undelivered parcel pending. Pay nominal fee of Rs 30 to reschedule delivery today: http://dtdc-redelivery.net", "label": "1", "category": "fake_delivery_fee", "source_id": "DS-01"},

    # 13. Other High-Risk Phishing & Loan Scams
    {"text": "Instant Personal Loan approved of Rs 5,00,000 with 0% interest and no CIBIL check! Disbursed in 5 minutes: https://instant-cash-loan-app.club", "label": "1", "category": "loan_phishing_scam", "source_id": "DS-01"},
    {"text": "Amazon Hiring: Part-time work from home opportunity! Earn Rs 2,500 to 5,000 daily by rating products. Contact manager on WhatsApp: https://wa.me/919876543210", "label": "1", "category": "job_lottery_scam", "source_id": "DS-01"},
    {"text": "PM Kisan Yojana: 17th installment of Rs 2,000 has been transferred. Check beneficiary status and verify biometric: https://pmkisan-gov-verify.com", "label": "1", "category": "loan_phishing_scam", "source_id": "DS-01"},
    {"text": "Download the new upgraded SBI Mobile Banking APK for seamless transactions: http://sbi-security-apk.download/sbi_v4.apk", "label": "1", "category": "loan_phishing_scam", "source_id": "DS-01"},
    {"text": "Enter your netbanking password and OTP on our security portal http://bank-safe-verify.info to stop card compromise.", "label": "1", "category": "loan_phishing_scam", "source_id": "DS-01"},

    # -----------------------------------------------------------------------
    # LEGITIMATE MESSAGES (Label: 0)
    # -----------------------------------------------------------------------
    # 14. Legitimate Bank Transactional Alerts (Debits, Credits, Statements)
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
    {"text": "Rs 250.00 paid to Mother Dairy via PhonePe from Kotak Mahindra Bank A/C XX1928 on 08-Nov-26. UTR 948201948201.", "label": "0", "category": "transactional_clean", "source_id": "DS-01"},
    {"text": "Dear customer, your recurring deposit installment of Rs 2,000 has been debited from account 4091 on 05-Nov-26 - Canara Bank.", "label": "0", "category": "transactional_clean", "source_id": "DS-01"},
    {"text": "Your credit card bill of Rs 14,290.00 for card ending 9012 is generated. Due date 20-Nov-26. Min due Rs 750.00 - HDFC Bank.", "label": "0", "category": "transactional_clean", "source_id": "DS-01"},
    {"text": "Dear SBI customer, your home loan EMI of Rs 32,450 for loan account 9019 has been credited for November 2026.", "label": "0", "category": "transactional_clean", "source_id": "DS-01"},
    {"text": "ATM Cash Withdrawal of Rs 5,000.00 made from A/C XX3910 at HDFC ATM MG ROAD on 06-Nov-26. Bal Rs 21,400.00.", "label": "0", "category": "transactional_clean", "source_id": "DS-01"},
    {"text": "Fastag account 849201 recharged with Rs 1,000.00 via UPI on 07-Nov-26. Current Fastag balance Rs 1,420.00.", "label": "0", "category": "transactional_clean", "source_id": "DS-01"},

    # 15. Legitimate Benign OTP Messages (No URLs, No Threats)
    {"text": "729401 is your Amazon login verification code. It is valid for 10 minutes. Do not share this code with anyone.", "label": "0", "category": "otp_clean", "source_id": "DS-01"},
    {"text": "581902 is your OTP to complete Swiggy order payment of Rs 480.00. Valid for 5 mins. Swiggy never asks for OTP.", "label": "0", "category": "otp_clean", "source_id": "DS-01"},
    {"text": "Google verification code: 394820. Do not share with anyone.", "label": "0", "category": "otp_clean", "source_id": "DS-01"},
    {"text": "Your one-time password for Zomato login is 6102. Valid for 10 minutes.", "label": "0", "category": "otp_clean", "source_id": "DS-01"},
    {"text": "Microsoft security code: 849201. Use this to verify identity.", "label": "0", "category": "otp_clean", "source_id": "DS-01"},
    {"text": "829471 is the OTP for registering Aadhaar on DigiLocker. Do not disclose to anyone.", "label": "0", "category": "otp_clean", "source_id": "DS-01"},
    {"text": "401928 is your OTP for Axis Bank NetBanking login. Valid for 3 minutes. Never disclose OTP over phone.", "label": "0", "category": "otp_clean", "source_id": "DS-01"},
    {"text": "Your OTP for Aadhaar authentication is 918230. Valid for 10 mins. UIDAI never calls to verify OTP.", "label": "0", "category": "otp_clean", "source_id": "DS-01"},
    {"text": "WhatsApp code: 492-109. You can also tap on the link to verify your phone.", "label": "0", "category": "otp_clean", "source_id": "DS-01"},
    {"text": "Uber verification code is 5019. Enter this to confirm your phone number.", "label": "0", "category": "otp_clean", "source_id": "DS-01"},

    # 16. Legitimate Conversational & Personal Messages
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
    {"text": "Flight got delayed by 30 minutes. Boarding should start around 6 PM.", "label": "0", "category": "conversational_clean", "source_id": "DS-01"},
    {"text": "Dinner is ready, please come downstairs when you finish your work call.", "label": "0", "category": "conversational_clean", "source_id": "DS-01"},

    # 17. Legitimate Commercial & Promotional (Not Scam)
    {"text": "Dominos Pizza: Flat 50% OFF on all pizzas today! Use coupon code FEAST50 on Dominos App. T&C apply.", "label": "0", "category": "promotional_clean", "source_id": "DS-01"},
    {"text": "Myntra End of Reason Sale starts midnight! Wishlist your favorite fashion brands now. Download Myntra app.", "label": "0", "category": "promotional_clean", "source_id": "DS-01"},
    {"text": "BookMyShow: Tickets for Coldplay India Tour are now live on BookMyShow. Reserve your seats today.", "label": "0", "category": "promotional_clean", "source_id": "DS-01"},
    {"text": "Cult.fit: Renew your annual gym membership today and get 2 months free extension. Offer ends Sunday.", "label": "0", "category": "promotional_clean", "source_id": "DS-01"},
    {"text": "Zomato Gold: Free delivery on all orders above Rs 199. Enjoy unlimited dining discounts across 2000+ restaurants.", "label": "0", "category": "promotional_clean", "source_id": "DS-01"},
    {"text": "Flipkart Big Billion Days: Up to 80% off on electronics, smartphones, and home appliances. Sale live now.", "label": "0", "category": "promotional_clean", "source_id": "DS-01"},
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
