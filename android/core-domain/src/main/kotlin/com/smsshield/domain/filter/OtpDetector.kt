package com.smsshield.domain.filter

import java.util.regex.Pattern

/**
 * Result classification of the OTP privacy check.
 */
sealed class OtpCheckResult {
    /** Pure transactional OTP message with no URLs or threats. Safe to bypass. */
    object BenignOtpOnly : OtpCheckResult()

    /** OTP mentioned alongside suspicious threats or phishing links. Requires active threat analysis. */
    data class SuspiciousOtpDemand(val reason: String) : OtpCheckResult()

    /** Standard message not centered on OTP authentication. */
    object NotOtpOnly : OtpCheckResult()
}

/**
 * Defensive OTP detection and privacy filtering.
 *
 * Protects user privacy by identifying authentic, benign OTP/verification code notifications
 * and avoiding unnecessary backend ingestion or transmission of one-time secrets.
 */
object OtpDetector {

    // Common numeric OTP indicators (4 to 8 digits)
    private val OTP_CODE_REGEX = Pattern.compile(
        """(?i)\b(?:\d{4,8})\b"""
    )

    private val OTP_KEYWORDS = listOf(
        "otp", "one time password", "verification code", "security code",
        "auth code", "login code", "passcode"
    )

    private val THREAT_KEYWORDS = listOf(
        "blocked", "suspended", "deactivated", "urgent", "kyc", "pan", "fine", "penalty"
    )

    /**
     * Inspects message text and extracted URLs to determine if it is an authentic OTP-only message.
     */
    fun evaluate(messageText: String?, urlCount: Int): OtpCheckResult {
        if (messageText.isNullOrBlank()) return OtpCheckResult.NotOtpOnly

        val lower = messageText.lowercase()
        val hasOtpKeyword = OTP_KEYWORDS.any { lower.contains(it) }
        val hasNumericCode = OTP_CODE_REGEX.matcher(messageText).find()

        if (!hasOtpKeyword && !hasNumericCode) {
            return OtpCheckResult.NotOtpOnly
        }

        // If message contains URLs, it is NEVER treated as pure benign OTP
        if (urlCount > 0) {
            return OtpCheckResult.SuspiciousOtpDemand("Message contains both verification codes and external web links")
        }

        // If message contains account suspension or KYC threats
        val matchedThreat = THREAT_KEYWORDS.firstOrNull { lower.contains(it) }
        if (matchedThreat != null) {
            return OtpCheckResult.SuspiciousOtpDemand("Message combines verification codes with urgent account threat: '$matchedThreat'")
        }

        // If it has OTP keywords + code, and NO urls or threats -> Benign OTP Only
        if (hasOtpKeyword && hasNumericCode) {
            return OtpCheckResult.BenignOtpOnly
        }

        return OtpCheckResult.NotOtpOnly
    }
}

