package com.smsshield.domain.model

/**
 * Domain API transfer objects matching FastAPI backend schemas.
 */

data class MessageScanApiRequest(
    val message_text: String,
    val source_type: String = "manual_paste",
    val source_package: String? = null,
    val extracted_urls: List<String>? = null
)

data class MessageScanApiResponse(
    val scan_id: String,
    val classification: String,
    val confidence: Double,
    val risk_score: Double,
    val reasons: List<String>,
    val extracted_urls: List<String>,
    val recommendation: String,
    val model_version: String,
    val timestamp: String
)

data class UrlScanApiRequest(
    val url: String
)

data class ProviderResultApiModel(
    val provider: String,
    val status: String,
    val threat_categories: List<String> = emptyList(),
    val reference_id: String? = null,
    val latency_ms: Int = 0,
    val message: String = ""
)

data class UrlScanApiResponse(
    val scan_id: String,
    val original_url: String,
    val normalized_url: String,
    val hostname: String,
    val is_ip_address: Boolean,
    val is_shortened: Boolean,
    val is_punycode: Boolean,
    val threat_intelligence_results: Map<String, ProviderResultApiModel> = emptyMap(),
    val final_url_classification: String,
    val risk_score: Double,
    val evidence: List<String>,
    val recommendation: String,
    val timestamp: String
)
