package com.smsshield.domain.model

/**
 * User privacy and monitoring preferences contract.
 * NON-NEGOTIABLE RULE: Monitoring is strictly disabled by default.
 */
data class UserPreferences(
    val isMonitoringEnabled: Boolean = false,
    val hasCompletedOnboarding: Boolean = false,
    val backendUrl: String = "http://10.0.2.2:8000",
    val dataRetentionDays: Int = 30
)

