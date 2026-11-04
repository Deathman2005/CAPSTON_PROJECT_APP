package com.smsshield.domain

import com.smsshield.domain.filter.OtpCheckResult
import com.smsshield.domain.filter.OtpDetector
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class OtpDetectorTest {

    @Test
    fun testAuthenticBenignOtpIsBypassed() {
        val message = "Your OTP is 492019 for login at Amazon. Do not share with anyone."
        val result = OtpDetector.evaluate(message, urlCount = 0)
        assertEquals(OtpCheckResult.BenignOtpOnly, result)

        val message2 = "782194 is your verification code for Swiggy food delivery."
        val result2 = OtpDetector.evaluate(message2, urlCount = 0)
        assertEquals(OtpCheckResult.BenignOtpOnly, result2)
    }

    @Test
    fun testOtpWithUrlIsMarkedSuspiciousNeverBypassed() {
        val phishingMessage = "Your OTP is 829104. Verify account immediately at http://bank-kyc.xyz/verify"
        val result = OtpDetector.evaluate(phishingMessage, urlCount = 1)
        assertTrue(result is OtpCheckResult.SuspiciousOtpDemand, "OTP combined with URL must be investigated")
    }

    @Test
    fun testOtpWithSuspensionThreatIsMarkedSuspicious() {
        val threatMessage = "Your SBI account is blocked. Use verification code 482910 to unlock."
        val result = OtpDetector.evaluate(threatMessage, urlCount = 0)
        assertTrue(result is OtpCheckResult.SuspiciousOtpDemand, "Account threat with OTP must be flagged")
    }

    @Test
    fun testNonOtpMessageReturnsNotOtpOnly() {
        val regularMessage = "Hi Mom, I will be home by 7 PM for dinner."
        val result = OtpDetector.evaluate(regularMessage, urlCount = 0)
        assertEquals(OtpCheckResult.NotOtpOnly, result)
    }
}

