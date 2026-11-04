package com.smsshield.app

import com.smsshield.app.data.local.ScanRecordEntity
import com.smsshield.app.service.SMSNotificationListener
import com.smsshield.domain.model.ScanItem
import com.smsshield.domain.model.SecurityClassification
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppFoundationTest {

    @Test
    fun testApprovedSmsPackageRegistry() {
        val approved = SMSNotificationListener.SUPPORTED_SMS_PACKAGES

        // Verify approved SMS packages
        assertTrue(approved.contains("com.google.android.apps.messaging"))
        assertTrue(approved.contains("com.samsung.android.messaging"))

        // Strictly verify that unrelated packages are NOT supported
        assertFalse(approved.contains("com.whatsapp"))
        assertFalse(approved.contains("org.telegram.messenger"))
        assertFalse(approved.contains("com.google.android.gm"))
        assertFalse(approved.contains("com.instagram.android"))
    }

    @Test
    fun testInitialServiceStateDisconnected() {
        assertFalse(SMSNotificationListener.isConnected)
    }

    @Test
    fun testScanRecordEntityDomainMapping() {
        val domainItem = ScanItem(
            id = "test-123",
            timestamp = 1730000000000L,
            classification = SecurityClassification.SUSPICIOUS,
            riskScore = 65.0,
            confidence = 0.88,
            urlCount = 1,
            extractedUrls = listOf("http://suspicious-link.top"),
            detectionReasons = listOf("Unverified external link"),
            recommendation = "Exercise caution with links.",
            sourceCategory = "manual_input"
        )

        // Convert domain to entity
        val entity = ScanRecordEntity.fromDomain(domainItem)
        assertEquals("test-123", entity.id)
        assertEquals("SUSPICIOUS", entity.classification)
        assertEquals(65.0, entity.riskScore)
        assertEquals("http://suspicious-link.top", entity.extractedUrlsString)
        assertEquals("Unverified external link", entity.detectionReasonsString)

        // Convert entity back to domain
        val mappedBack = entity.toDomain()
        assertEquals(domainItem.id, mappedBack.id)
        assertEquals(domainItem.classification, mappedBack.classification)
        assertEquals(domainItem.riskScore, mappedBack.riskScore)
        assertEquals(domainItem.extractedUrls, mappedBack.extractedUrls)
        assertEquals(domainItem.detectionReasons, mappedBack.detectionReasons)
    }
}
