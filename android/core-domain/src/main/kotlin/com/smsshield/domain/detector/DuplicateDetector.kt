package com.smsshield.domain.detector

import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

/**
 * Result returned by the duplicate and rate-limiting check.
 */
sealed class IngestionCheckResult {
    object Accepted : IngestionCheckResult()
    data class Duplicate(val originalTimestamp: Long) : IngestionCheckResult()
    data class RateLimited(val maxPerMinute: Int) : IngestionCheckResult()
}

/**
 * Time-windowed deduplication and rate limiter for incoming SMS notifications.
 *
 * Prevents redundant processing of repeated system notifications while protecting
 * device battery and CPU from notification storms.
 */
class DuplicateDetector(
    private val deduplicationWindowMs: Long = 60_000L, // 60 seconds
    private val maxEventsPerMinute: Int = 15
) {
    // Fingerprint -> timestamp when first ingested
    private val recentFingerprints = ConcurrentHashMap<String, Long>()

    // Sliding timestamp history for rate-limiting
    private val eventTimestamps = mutableListOf<Long>()
    private val lock = Any()

    /**
     * Checks if an incoming notification is a duplicate or if the rate limit is exceeded.
     * Automatically registers the notification if accepted.
     */
    fun checkAndRecord(
        packageName: String,
        sender: String?,
        messageText: String,
        currentTimeMs: Long = System.currentTimeMillis()
    ): IngestionCheckResult {
        synchronized(lock) {
            pruneExpired(currentTimeMs)

            // 1. Rate Limiting Check
            if (eventTimestamps.size >= maxEventsPerMinute) {
                return IngestionCheckResult.RateLimited(maxEventsPerMinute)
            }

            // 2. Duplicate Detection Check
            val fingerprint = computeFingerprint(packageName, sender, messageText)
            val existingTimestamp = recentFingerprints[fingerprint]

            if (existingTimestamp != null && (currentTimeMs - existingTimestamp) < deduplicationWindowMs) {
                return IngestionCheckResult.Duplicate(existingTimestamp)
            }

            // Accept and record
            recentFingerprints[fingerprint] = currentTimeMs
            eventTimestamps.add(currentTimeMs)
            return IngestionCheckResult.Accepted
        }
    }

    /**
     * Cleans up expired entries outside the sliding window.
     */
    fun pruneExpired(currentTimeMs: Long = System.currentTimeMillis()) {
        synchronized(lock) {
            // Prune fingerprints older than deduplicationWindowMs
            recentFingerprints.entries.removeIf { (_, ts) ->
                (currentTimeMs - ts) >= deduplicationWindowMs
            }

            // Prune rate-limiter timestamps older than 60 seconds
            eventTimestamps.removeIf { ts ->
                (currentTimeMs - ts) >= 60_000L
            }
        }
    }

    /**
     * Clears all recorded fingerprints and timestamps (e.g. for testing).
     */
    fun reset() {
        synchronized(lock) {
            recentFingerprints.clear()
            eventTimestamps.clear()
        }
    }

    private fun computeFingerprint(packageName: String, sender: String?, messageText: String): String {
        val raw = "$packageName||${sender ?: ""}||${messageText.trim()}"
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(raw.toByteArray(Charsets.UTF_8))
        return hashBytes.joinToString("") { "%02x".format(it) }
    }
}
