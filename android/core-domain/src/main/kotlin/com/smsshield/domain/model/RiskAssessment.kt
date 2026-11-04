package com.smsshield.domain.model

/**
 * Standard security classification status.
 */
enum class SecurityClassification {
    SAFE,
    SUSPICIOUS,
    MALICIOUS,
    UNKNOWN
}

/**
 * Core risk assessment decision contract.
 */
data class RiskAssessment(
    val classification: SecurityClassification,
    val riskScore: Double?,
    val confidence: Double,
    val primaryCategory: ThreatCategory,
    val detectionReasons: List<String>,
    val recommendation: String,
    val timestampUtcIso: String
)
