package com.smsshield.domain

import com.smsshield.domain.detector.DuplicateDetector
import com.smsshield.domain.detector.IngestionCheckResult
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DuplicateDetectorTest {

    private lateinit var detector: DuplicateDetector

    @BeforeTest
    fun setUp() {
        detector = DuplicateDetector(
            deduplicationWindowMs = 60_000L,
            maxEventsPerMinute = 5 // low limit for quick rate-limiting test
        )
    }

    @Test
    fun testFirstArrivalIsAccepted() {
        val result = detector.checkAndRecord(
            packageName = "com.google.android.apps.messaging",
            sender = "SBI-ALERT",
            messageText = "Your account was credited with INR 5,000",
            currentTimeMs = 1000L
        )
        assertEquals(IngestionCheckResult.Accepted, result)
    }

    @Test
    fun testDuplicateWithinWindowIsRejected() {
        val pkg = "com.google.android.apps.messaging"
        val sender = "HDFC-BANK"
        val text = "Your statement for October is ready"

        val first = detector.checkAndRecord(pkg, sender, text, currentTimeMs = 10_000L)
        assertEquals(IngestionCheckResult.Accepted, first)

        // Same notification arrives 5 seconds later (e.g. notification update)
        val second = detector.checkAndRecord(pkg, sender, text, currentTimeMs = 15_000L)
        assertTrue(second is IngestionCheckResult.Duplicate)
        assertEquals(10_000L, second.originalTimestamp)
    }

    @Test
    fun testDuplicateExpiresAfterWindow() {
        val pkg = "com.google.android.apps.messaging"
        val sender = "HDFC-BANK"
        val text = "Your statement for October is ready"

        detector.checkAndRecord(pkg, sender, text, currentTimeMs = 10_000L)

        // Arrives 65 seconds later (outside 60s window)
        val later = detector.checkAndRecord(pkg, sender, text, currentTimeMs = 75_000L)
        assertEquals(IngestionCheckResult.Accepted, later)
    }

    @Test
    fun testDifferentMessagesFromSamePackageAccepted() {
        val pkg = "com.google.android.apps.messaging"
        val r1 = detector.checkAndRecord(pkg, "BANK-A", "First SMS message", currentTimeMs = 1000L)
        val r2 = detector.checkAndRecord(pkg, "BANK-A", "Second distinct message", currentTimeMs = 2000L)

        assertEquals(IngestionCheckResult.Accepted, r1)
        assertEquals(IngestionCheckResult.Accepted, r2)
    }

    @Test
    fun testRateLimiterEnforcement() {
        val pkg = "com.google.android.apps.messaging"

        // Capacity is 5 per minute
        for (i in 1..5) {
            val res = detector.checkAndRecord(pkg, "SENDER", "Message #$i", currentTimeMs = 1000L + (i * 100))
            assertEquals(IngestionCheckResult.Accepted, res, "Event $i should be accepted")
        }

        // 6th event within same minute must be rate limited
        val sixth = detector.checkAndRecord(pkg, "SENDER", "Message #6", currentTimeMs = 2000L)
        assertTrue(sixth is IngestionCheckResult.RateLimited)
        assertEquals(5, sixth.maxPerMinute)
    }
}
