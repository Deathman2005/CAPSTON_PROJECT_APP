package com.smsshield.app.service

import android.app.Notification
import android.os.Bundle
import android.service.notification.StatusBarNotification
import android.util.Log
import com.smsshield.domain.filter.OtpCheckResult
import com.smsshield.domain.filter.OtpDetector
import com.smsshield.domain.parser.ExtractedUrl
import com.smsshield.domain.parser.UrlExtractor
import com.smsshield.domain.registry.SupportedSmsApps

/**
 * Clean data structure holding parsed notification content and metadata.
 */
data class ParsedSmsNotification(
    val packageName: String,
    val sender: String?,
    val messageText: String,
    val extractedUrls: List<ExtractedUrl>,
    val isOtpOnly: Boolean,
    val timestamp: Long
)

/**
 * Result returned by the notification parser.
 */
sealed class NotificationParseResult {
    data class Success(val parsed: ParsedSmsNotification) : NotificationParseResult()
    object RedactedOrEmpty : NotificationParseResult()
    data class IgnoredUnsupportedPackage(val packageName: String) : NotificationParseResult()
    data class BypassedBenignOtp(val sender: String?) : NotificationParseResult()
}

/**
 * Defensive parser for incoming Android notifications.
 *
 * Extracts sender and visible text defensively across multiple notification formats
 * (standard text, BigTextStyle, and MessagingStyle) while ensuring strict zero-logging
 * of raw SMS text.
 */
object NotificationParser {

    private const val TAG = "NotificationParser"

    /**
     * Parses a StatusBarNotification event defensively.
     */
    fun parse(sbn: StatusBarNotification?): NotificationParseResult {
        if (sbn == null) return NotificationParseResult.RedactedOrEmpty

        val packageName = sbn.packageName
        if (!SupportedSmsApps.isSupported(packageName)) {
            return NotificationParseResult.IgnoredUnsupportedPackage(packageName)
        }

        val notification = sbn.notification ?: return NotificationParseResult.RedactedOrEmpty
        val extras: Bundle = notification.extras ?: return NotificationParseResult.RedactedOrEmpty

        // Extract sender / title
        val title = extractTitle(extras)

        // Extract visible message text across styles
        val text = extractBodyText(extras)

        if (text.isNullOrBlank()) {
            Log.d(TAG, "Notification content from $packageName is empty or redacted by OS.")
            return NotificationParseResult.RedactedOrEmpty
        }

        // Extract and analyze URLs
        val extractedUrls = UrlExtractor.analyzeUrls(text)

        // Privacy check: Avoid processing benign OTP-only notifications
        val otpResult = OtpDetector.evaluate(text, extractedUrls.size)
        if (otpResult is OtpCheckResult.BenignOtpOnly) {
            Log.d(TAG, "Bypassed benign transactional OTP notification from $packageName to preserve user privacy.")
            return NotificationParseResult.BypassedBenignOtp(title)
        }

        // Diagnostic log without leaking raw message body
        Log.i(TAG, "Successfully parsed SMS notification from $packageName [length=${text.length}, urls=${extractedUrls.size}]")

        val parsed = ParsedSmsNotification(
            packageName = packageName,
            sender = title,
            messageText = text,
            extractedUrls = extractedUrls,
            isOtpOnly = false,
            timestamp = sbn.postTime
        )

        return NotificationParseResult.Success(parsed)
    }

    private fun extractTitle(extras: Bundle): String? {
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)
            ?: extras.getCharSequence(Notification.EXTRA_TITLE_BIG)
            ?: extras.getCharSequence(Notification.EXTRA_CONVERSATION_TITLE)
        return title?.toString()?.trim()
    }

    private fun extractBodyText(extras: Bundle): String? {
        // 1. Check EXTRA_BIG_TEXT (expanded text typically contains full SMS)
        val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()
        if (!bigText.isNullOrBlank()) {
            return bigText.trim()
        }

        // 2. Check Notification.MessagingStyle messages
        val messages = extras.getParcelableArray(Notification.EXTRA_MESSAGES)
        if (!messages.isNullOrEmpty()) {
            val lastMessage = messages.lastOrNull()
            if (lastMessage is Bundle) {
                val msgText = lastMessage.getCharSequence("text")?.toString()
                if (!msgText.isNullOrBlank()) {
                    return msgText.trim()
                }
            }
        }

        // 3. Fall back to standard EXTRA_TEXT
        val standardText = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()
        if (!standardText.isNullOrBlank()) {
            return standardText.trim()
        }

        // 4. Fall back to EXTRA_SUB_TEXT or EXTRA_INFO_TEXT if exposed
        val subText = extras.getCharSequence(Notification.EXTRA_SUB_TEXT)?.toString()
        if (!subText.isNullOrBlank()) {
            return subText.trim()
        }

        return null
    }
}

