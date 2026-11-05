package com.smsshield.domain

import com.smsshield.domain.alert.AlertDecisionEngine
import com.smsshield.domain.alert.AlertPriority
import com.smsshield.domain.model.ScanItem
import com.smsshield.domain.model.SecurityClassification
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import java.util.UUID

class AlertDecisionEngineTest {

    @Test
    fun testMaliciousScanTriggersHighPriorityAlert() {
        val scan = ScanItem(
            id = UUID.randomUUID().toString(),
            timestamp = System.currentTimeMillis(),
            classification = SecurityClassification.MALICIOUS,
            riskScore = 95.0,
            confidence = 0.95,
            urlCount = 1,
            extractedUrls = listOf("http://sbi-kyc-update.com/login"),
            detectionReasons = listOf("Urgent threat of account deactivation", "Contains unverified link"),
            recommendation = "DO NOT click links or supply credentials.",
            sourceCategory = "notification_auto"
        )

        val alert = AlertDecisionEngine.evaluate(scan)

        assertTrue(alert.shouldAlert, "Malicious scan must trigger alert")
        assertEquals(AlertPriority.HIGH, alert.priority, "Malicious scan must be HIGH priority")
        assertTrue(alert.title.contains("Dangerous Scam"), "Alert title must reflect dangerous scam")
        assertTrue(alert.body.contains("95"), "Alert body must include risk score")
        assertEquals(scan.id, alert.scanId, "Scan ID must match")
    }

    @Test
    fun testSuspiciousScanTriggersDefaultPriorityAlert() {
        val scan = ScanItem(
            id = UUID.randomUUID().toString(),
            timestamp = System.currentTimeMillis(),
            classification = SecurityClassification.SUSPICIOUS,
            riskScore = 65.0,
            confidence = 0.85,
            urlCount = 1,
            extractedUrls = listOf("http://promo-win.org"),
            detectionReasons = listOf("Message contains external web link"),
            recommendation = "Exercise caution with unverified links.",
            sourceCategory = "notification_auto"
        )

        val alert = AlertDecisionEngine.evaluate(scan)

        assertTrue(alert.shouldAlert, "Suspicious scan must trigger alert")
        assertEquals(AlertPriority.DEFAULT, alert.priority, "Suspicious scan must be DEFAULT priority")
        assertTrue(alert.title.contains("Suspicious Message"), "Alert title must reflect suspicious message")
        assertTrue(alert.body.contains("65"), "Alert body must include risk score")
    }

    @Test
    fun testSafeScanDoesNotAlert() {
        val scan = ScanItem(
            id = UUID.randomUUID().toString(),
            timestamp = System.currentTimeMillis(),
            classification = SecurityClassification.SAFE,
            riskScore = 10.0,
            confidence = 0.99,
            urlCount = 0,
            extractedUrls = emptyList(),
            detectionReasons = emptyList(),
            recommendation = "Message appears authentic.",
            sourceCategory = "notification_auto"
        )

        val alert = AlertDecisionEngine.evaluate(scan)

        assertFalse(alert.shouldAlert, "Safe scan must not trigger alert")
        assertEquals(AlertPriority.NONE, alert.priority, "Safe scan priority must be NONE")
    }

    @Test
    fun testUnknownScanDoesNotAlert() {
        val scan = ScanItem(
            id = UUID.randomUUID().toString(),
            timestamp = System.currentTimeMillis(),
            classification = SecurityClassification.UNKNOWN,
            riskScore = 45.0,
            confidence = 0.50,
            urlCount = 1,
            extractedUrls = listOf("http://new-domain.io"),
            detectionReasons = listOf("Threat intelligence services unreachable"),
            recommendation = "Caution advised; threat intelligence unavailable.",
            sourceCategory = "notification_auto"
        )

        val alert = AlertDecisionEngine.evaluate(scan)

        assertFalse(alert.shouldAlert, "Unknown scan must not trigger alert")
        assertEquals(AlertPriority.NONE, alert.priority, "Unknown scan priority must be NONE")
    }

    @Test
    fun testAlertPayloadNeverLeaksRawMessageTextOrOtp() {
        val rawSensitiveOtp = "948201"
        val rawMessage = "Your secret SBI netbanking OTP is $rawSensitiveOtp. Never share it."

        val scan = ScanItem(
            id = "test-scan-privacy-123",
            timestamp = System.currentTimeMillis(),
            classification = SecurityClassification.MALICIOUS,
            riskScore = 98.0,
            confidence = 0.98,
            urlCount = 0,
            extractedUrls = emptyList(),
            detectionReasons = listOf("Credential harvesting demand"),
            recommendation = "Never share OTP or banking credentials.",
            sourceCategory = "notification_auto"
        )

        val alert = AlertDecisionEngine.evaluate(scan)

        assertFalse(alert.title.contains(rawSensitiveOtp), "Alert title must never contain raw OTP")
        assertFalse(alert.body.contains(rawSensitiveOtp), "Alert body must never contain raw OTP")
        assertFalse(alert.title.contains(rawMessage), "Alert title must never contain raw message")
        assertFalse(alert.body.contains(rawMessage), "Alert body must never contain raw message")
    }
}
