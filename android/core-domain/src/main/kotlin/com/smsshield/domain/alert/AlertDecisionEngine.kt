package com.smsshield.domain.alert

/**
 * Alert decision engine for evaluating when security warning notifications must be displayed.
 */

import com.smsshield.domain.model.SecurityClassification
import com.smsshield.domain.model.ScanItem

enum class AlertPriority {
    HIGH,
    DEFAULT,
    NONE
}

data class AlertNotificationPayload(
    val shouldAlert: Boolean,
    val priority: AlertPriority,
    val title: String,
    val body: String,
    val riskScore: Double?,
    val scanId: String,
    val recommendation: String
)

object AlertDecisionEngine {

    /**
     * Determines whether an incoming scan result warrants an intrusive user notification.
     * Enforces privacy by ensuring raw message content and verification codes are never
     * exposed in the notification banner.
     */
    fun evaluate(scan: ScanItem): AlertNotificationPayload {
        return when (scan.classification) {
            SecurityClassification.MALICIOUS -> {
                val scoreDisplay = scan.riskScore?.let { "[Risk ${it.toInt()}/100] " } ?: ""
                val customTitle = scan.explanation?.summary_title?.takeIf { it.isNotBlank() }?.let { "⚠️ Dangerous Scam: $it" }
                    ?: "⚠️ Dangerous Scam Detected"
                val reason = scan.explanation?.why_flagged?.takeIf { it.isNotBlank() }
                    ?: scan.detectionReasons.firstOrNull()?.takeIf { it.isNotBlank() }
                    ?: "Fraudulent SMS detected. Do not click links or provide credentials."

                AlertNotificationPayload(
                    shouldAlert = true,
                    priority = AlertPriority.HIGH,
                    title = customTitle,
                    body = "${scoreDisplay}${reason}",
                    riskScore = scan.riskScore,
                    scanId = scan.id,
                    recommendation = scan.recommendation
                )
            }
            SecurityClassification.SUSPICIOUS -> {
                val scoreDisplay = scan.riskScore?.let { "[Risk ${it.toInt()}/100] " } ?: ""
                val customTitle = scan.explanation?.summary_title?.takeIf { it.isNotBlank() }?.let { "⚡ Suspicious Message: $it" }
                    ?: "⚡ Suspicious Message Alert"
                val reason = scan.explanation?.why_flagged?.takeIf { it.isNotBlank() }
                    ?: scan.detectionReasons.firstOrNull()?.takeIf { it.isNotBlank() }
                    ?: "Message exhibits risk indicators. Exercise caution before proceeding."

                AlertNotificationPayload(
                    shouldAlert = true,
                    priority = AlertPriority.DEFAULT,
                    title = customTitle,
                    body = "${scoreDisplay}${reason}",
                    riskScore = scan.riskScore,
                    scanId = scan.id,
                    recommendation = scan.recommendation
                )
            }
            SecurityClassification.SAFE, SecurityClassification.UNKNOWN -> {
                AlertNotificationPayload(
                    shouldAlert = false,
                    priority = AlertPriority.NONE,
                    title = "",
                    body = "",
                    riskScore = scan.riskScore,
                    scanId = scan.id,
                    recommendation = scan.recommendation
                )
            }
        }
    }
}
