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
                AlertNotificationPayload(
                    shouldAlert = true,
                    priority = AlertPriority.HIGH,
                    title = "⚠️ Dangerous Scam Detected",
                    body = "${scoreDisplay}Fraudulent SMS detected. Do not click links or provide credentials.",
                    riskScore = scan.riskScore,
                    scanId = scan.id,
                    recommendation = scan.recommendation
                )
            }
            SecurityClassification.SUSPICIOUS -> {
                val scoreDisplay = scan.riskScore?.let { "[Risk ${it.toInt()}/100] " } ?: ""
                AlertNotificationPayload(
                    shouldAlert = true,
                    priority = AlertPriority.DEFAULT,
                    title = "⚡ Suspicious Message Alert",
                    body = "${scoreDisplay}Message exhibits risk indicators. Exercise caution before proceeding.",
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
