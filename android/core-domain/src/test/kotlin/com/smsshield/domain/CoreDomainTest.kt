package com.smsshield.domain

import com.smsshield.domain.model.RiskAssessment
import com.smsshield.domain.model.SecurityClassification
import com.smsshield.domain.model.ThreatCategory
import com.smsshield.domain.parser.UrlExtractor
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CoreDomainTest {

    @Test
    fun testSingleUrlExtraction() {
        val message = "Dear customer, click https://secure-bank.example.com to verify your PAN."
        val urls = UrlExtractor.extractUrls(message)
        assertEquals(1, urls.size)
        assertEquals("https://secure-bank.example.com", urls[0])
    }

    @Test
    fun testTrailingPunctuationRemoval() {
        val message = "Urgent: Visit https://kyc-update.org/login. Your account is on hold!"
        val urls = UrlExtractor.extractUrls(message)
        assertEquals(1, urls.size)
        assertEquals("https://kyc-update.org/login", urls[0])
    }

    @Test
    fun testMultipleUrlsExtraction() {
        val message = "Check https://link1.com and https://link2.org for updates."
        val urls = UrlExtractor.extractUrls(message)
        assertEquals(2, urls.size)
        assertTrue(urls.contains("https://link1.com"))
        assertTrue(urls.contains("https://link2.org"))
    }

    @Test
    fun testEmailAddressNotTreatedAsUrl() {
        val message = "Contact support@sbi.co.in for immediate assistance."
        val urls = UrlExtractor.extractUrls(message)
        assertTrue(urls.isEmpty(), "Email address should not be parsed as a URL")
    }

    @Test
    fun testNoUrlExtraction() {
        val message = "Your OTP for transaction at Amazon is 482910. Do not share with anyone."
        val urls = UrlExtractor.extractUrls(message)
        assertTrue(urls.isEmpty())
    }

    @Test
    fun testRiskAssessmentModelIntegrity() {
        val assessment = RiskAssessment(
            classification = SecurityClassification.MALICIOUS,
            riskScore = 95.0,
            confidence = 0.92,
            primaryCategory = ThreatCategory.BANK_IMPERSONATION,
            detectionReasons = listOf("Urgent KYC demand", "Phishing domain detected"),
            recommendation = "Do not open link.",
            timestampUtcIso = "2026-11-04T15:00:00Z"
        )
        assertEquals(SecurityClassification.MALICIOUS, assessment.classification)
        assertEquals(95.0, assessment.riskScore)
        assertEquals(ThreatCategory.BANK_IMPERSONATION, assessment.primaryCategory)
    }
}
