package com.smsshield.domain.model

/**
 * Domain representation of an analyzed SMS or URL scan.
 * STRICT PRIVACY REQUIREMENT: Raw message text is NEVER stored.
 */
data class ScanItem(
    val id: String,
    val timestamp: Long,
    val classification: SecurityClassification,
    val riskScore: Double?,
    val confidence: Double,
    val urlCount: Int,
    val extractedUrls: List<String>,
    val detectionReasons: List<String>,
    val recommendation: String,
    val sourceCategory: String
)

