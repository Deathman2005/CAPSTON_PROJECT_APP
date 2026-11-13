# SMS Shield — Test Cases & Fraud Samples for Verification

Use these curated test samples to test the **Android App Threat Scanner**, **Real-Time Notification Guard**, and **Backend AI Engine**.

---

## 1. UPI Payment & Collect Scams (Copy & Paste into SMS or QR Tab)

### Test 1: Fake UPI Collect Request ("Approve to Receive")
* **Category:** `fake_upi_collect_request`
* **Expected Classification:** `MALICIOUS`
* **Test Message:**
```text
Approve UPI collect request of INR 4,999 from user cashback@ybl to receive payment into your bank account.
```
* **What to observe:** The app flags the collect deception, explains that approving requests debits money, and displays safety warnings in both English and Hindi.

---

### Test 2: QR Code Payment Trap ("Scan to Claim Cashback")
* **Category:** `qr_code_scam`
* **Expected Classification:** `MALICIOUS`
* **Test Message (SMS):**
```text
Scan this QR code to claim your reward of INR 2,000 immediately into your bank account.
```
* **UPI Intent Link (Paste into "UPI / QR Code" tab):**
```text
upi://pay?pa=cashback_claim@upi&pn=Reward+Department&am=2000.00&tn=Scan+to+receive+Rs+2000+cashback
```
* **What to observe:** The scanner identifies the deceptive credit note (`tn`), extracts the payee VPA, and warns: *"Scanning a QR code only DEBITS money. You never need to enter a UPI PIN to receive money."*

---

### Test 3: Fake Payment Confirmation (Seller Trap)
* **Category:** `fake_payment_confirmation`
* **Expected Classification:** `MALICIOUS` / `SUSPICIOUS`
* **Test Message:**
```text
Payment Successful: You received Rs 12,500 on PhonePe from buyer. Confirm transaction receipt at http://phonepe-receive-ack.cc
```
* **What to observe:** The app flags the unverified receipt, highlights the risk tokens, and reminds sellers to verify their balance directly inside their banking app.

---

### Test 4: Fake Refund Scam
* **Category:** `fake_refund_scam`
* **Expected Classification:** `MALICIOUS`
* **Test Message:**
```text
Your refund of Rs 1,499 is pending. Approve payment request in Google Pay to credit money to your account.
```

---

### Test 5: Duplicate Payment Scam
* **Category:** `duplicate_payment_scam`
* **Expected Classification:** `MALICIOUS`
* **Test Message:**
```text
Previous payment of INR 850 failed. Please pay again immediately to complete transaction.
```

---

## 2. Banking, KYC & Identity Threat Scams

### Test 6: Fake Bank KYC Update SMS
* **Category:** `fake_kyc_update`
* **Expected Classification:** `MALICIOUS` (Risk Score: 90+)
* **Test Message:**
```text
Your SBI bank account is suspended. Update your PAN / KYC immediately at http://sbi-kyc-update.com
```
* **What to observe:** Words like `suspended`, `PAN`, `KYC`, `immediately` highlighted in red; explanation warns that banks never send SMS links for KYC.

---

### Test 7: Bank Account Suspension Scam
* **Category:** `bank_suspension_scam`
* **Expected Classification:** `MALICIOUS`
* **Test Message:**
```text
Your HDFC account has been blocked due to suspicious activity. Verify now at http://hdfc-security.in
```

---

### Test 8: Fake Customer Care & AnyDesk Remote Access
* **Category:** `fake_customer_care`
* **Expected Classification:** `MALICIOUS`
* **Test Message:**
```text
Dear customer, call ICICI care at 9876543210 and install AnyDesk to verify your account and reverse charges.
```
* **What to observe:** High risk score; flags remote screen-sharing risks (`AnyDesk`) and personal phone numbers.

---

## 3. Utility, Telecom & Delivery Scams

### Test 9: Electricity Bill Disconnection Scam (Very Common in India)
* **Category:** `electricity_disconnection_scam`
* **Expected Classification:** `MALICIOUS`
* **Test Message:**
```text
Your electricity power will be disconnected at 9:30 PM tonight due to unpaid bill. Call officer at 8877665544 immediately.
```
* **What to observe:** Detects fake urgency (`disconnected tonight`), flags personal contact number, and advises verifying with official state electricity distribution boards.

---

### Test 10: SIM-Blocking Telecom Scam
* **Category:** `sim_blocking_scam`
* **Expected Classification:** `MALICIOUS`
* **Test Message:**
```text
Your Jio SIM will be deactivated today. Call customer executive at 9988776655 to complete eKYC verification.
```

---

### Test 11: Fake Delivery / Courier Customs Fee Scam
* **Category:** `fake_delivery_fee`
* **Expected Classification:** `MALICIOUS`
* **Test Message:**
```text
India Post: Your package is detained at depot. Pay unpaid customs fee of Rs 25 at http://indiapost-parcel.link
```

---

### Test 12: Cashback & Lottery Reward Scam
* **Category:** `cashback_reward_scam`
* **Expected Classification:** `MALICIOUS`
* **Test Message:**
```text
Congratulations! You have won Rs 5,000 scratch card. Click here to claim into UPI: http://reward-claim.online
```

---

## 4. Legitimate Clean Messages (Safe Verification)

### Test 13: Clean Banking Debit Alert
* **Category:** `safe_transaction`
* **Expected Classification:** `SAFE` (Risk Score: < 25)
* **Test Message:**
```text
Rs. 450.00 debited from A/c XX4021 on 09-NOV-26 at Swiggy. Available Bal: Rs 14,230.12. Ref 9283719.
```
* **What to observe:** Safe green badge; verified as standard transactional SMS with zero false alarms.

---

### Test 14: Clean OTP Authentication SMS
* **Category:** `safe_transaction`
* **Expected Classification:** `SAFE`
* **Test Message:**
```text
184920 is your verification OTP for logging into HDFC NetBanking. Do not share this OTP with anyone including bank staff.
```

---

### Test 15: Legitimate Merchant UPI QR Code (Paste into "UPI / QR Code" tab)
* **Category:** `upi_intent`
* **Expected Classification:** `SAFE`
* **UPI Intent Link:**
```text
upi://pay?pa=starbucks@hdfcbank&pn=Starbucks+Coffee&am=350.00&mc=5812&tn=Coffee+Order
```
* **What to observe:** Verified HDFC Bank PSP handle, identified coffee merchant code `5812`, verified standard purchase amount.

