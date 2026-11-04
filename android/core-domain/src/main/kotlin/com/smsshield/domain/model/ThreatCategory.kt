package com.smsshield.domain.model

/**
 * High-level detection categories supported by SMS Shield.
 */
enum class ThreatCategory(val displayName: String) {
    BANK_IMPERSONATION("Bank Impersonation"),
    UPI_FRAUD("UPI / Payment Fraud"),
    KYC_UPDATE("Fake KYC Update"),
    OTP_THEFT("OTP & Credential Theft"),
    PHISHING_URL("Phishing Link"),
    FAKE_DELIVERY("Fake Delivery Notification"),
    LOTTERY_PRIZE("Lottery & Prize Scam"),
    INVESTMENT_LOAN("Investment & Loan Scam"),
    MALWARE_DISTRIBUTION("Malware-Hosting URL"),
    BENIGN("Legitimate Transaction / Communication"),
    UNKNOWN("Indeterminate / Insufficient Evidence")
}
