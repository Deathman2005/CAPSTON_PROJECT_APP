package com.smsshield.domain

import com.smsshield.domain.parser.UrlExtractor
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class UrlExtractorPhase2Test {

    @Test
    fun testCase1_OneUrl() {
        val message = "Dear user, check your invoice at https://billing.example.com"
        val urls = UrlExtractor.extractUrls(message)
        assertEquals(1, urls.size)
        assertEquals("https://billing.example.com", urls[0])
    }

    @Test
    fun testCase2_MultipleUrls() {
        val message = "Review terms at https://terms.example.com and policy at http://privacy.example.org/v2"
        val urls = UrlExtractor.extractUrls(message)
        assertEquals(2, urls.size)
        assertTrue(urls.contains("https://terms.example.com"))
        assertTrue(urls.contains("http://privacy.example.org/v2"))
    }

    @Test
    fun testCase3_NoUrl() {
        val message = "Your appointment is confirmed for tomorrow at 10:30 AM."
        val urls = UrlExtractor.extractUrls(message)
        assertTrue(urls.isEmpty())
    }

    @Test
    fun testCase4_ShortenedUrl() {
        val message = "Urgent: claim refund at https://bit.ly/3xY892 or http://tinyurl.com/sbi-claim"
        val analyzed = UrlExtractor.analyzeUrls(message)
        assertEquals(2, analyzed.size)
        assertTrue(analyzed[0].isShortened)
        assertTrue(analyzed[1].isShortened)
    }

    @Test
    fun testCase5_UnicodeHostname() {
        val message = "Visit https://xn--sbi-9o0a.com/login for verification"
        val analyzed = UrlExtractor.analyzeUrls(message)
        assertEquals(1, analyzed.size)
        assertTrue(analyzed[0].isPunycode, "Punycode domain must be identified")
    }

    @Test
    fun testCase6_MalformedUrl() {
        val message = "Check this broken link http:///broken..url and https:// valid but malformed"
        // Should not crash and should gracefully handle malformed tokens
        val urls = UrlExtractor.extractUrls(message)
        assertTrue(urls.none { it.contains(" ") })
    }

    @Test
    fun testCase7_PunctuationAfterUrl() {
        val message = "Update KYC at https://sbi-verify.org/portal. Do it immediately!"
        val urls = UrlExtractor.extractUrls(message)
        assertEquals(1, urls.size)
        assertEquals("https://sbi-verify.org/portal", urls[0], "Trailing period must be stripped")

        val message2 = "See details (https://bank.com/terms), and sign up."
        val urls2 = UrlExtractor.extractUrls(message2)
        assertEquals(1, urls2.size)
        assertEquals("https://bank.com/terms", urls2[0], "Enclosing brackets and trailing comma must be stripped")
    }

    @Test
    fun testCase8_UrlEmbeddedInSentence() {
        val message = "Before 5pm go to https://pay.gov.in/direct-tax to deposit tax."
        val urls = UrlExtractor.extractUrls(message)
        assertEquals(1, urls.size)
        assertEquals("https://pay.gov.in/direct-tax", urls[0])
    }

    @Test
    fun testCase9_NonUrlText() {
        val message = "Version 2.0.4 released on 2026.11.04 with 4.5 star rating."
        val urls = UrlExtractor.extractUrls(message)
        assertTrue(urls.isEmpty(), "Semantic version numbers and dates must not be parsed as URLs")
    }

    @Test
    fun testCase10_EmailAddress() {
        val message = "For support contact us at grievance@rbi.org.in or helpdesk@icici.com."
        val urls = UrlExtractor.extractUrls(message)
        assertTrue(urls.isEmpty(), "Email addresses must never be parsed as URLs")
    }

    @Test
    fun testSuspiciousIpAddressUrl() {
        val message = "Access administrative router console at http://192.168.1.1/login or http://45.33.32.156:8080/portal"
        val analyzed = UrlExtractor.analyzeUrls(message)
        assertEquals(2, analyzed.size)
        assertTrue(analyzed[0].isIpAddress, "192.168.1.1 must be recognized as IP address")
        assertTrue(analyzed[1].isIpAddress, "45.33.32.156 must be recognized as IP address")
    }

    @Test
    fun testDeceptiveSubdomainDetection() {
        val message = "Verify account at http://sbi.bank.account-update.xyz/login"
        val analyzed = UrlExtractor.analyzeUrls(message)
        assertEquals(1, analyzed.size)
        assertTrue(analyzed[0].hasDeceptiveSubdomains, "Deceptive banking keywords on suspicious TLD must be detected")
    }
}
