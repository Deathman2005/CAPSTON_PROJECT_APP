package com.smsshield.domain.model

/**
 * Android client backend connectivity health model.
 */
data class BackendHealth(
    val status: String,
    val appName: String,
    val version: String,
    val databaseConnected: Boolean,
    val latencyMs: Double?
)
