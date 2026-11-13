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

data class HindiExplanationApiModel(
    val summary_title: String,
    val why_flagged: String,
    val recommended_actions: List<String> = emptyList()
)

data class TokenSpanApiModel(
    val token: String,
    val weight: Double,
    val impact: String,
    val start: Int,
    val end: Int
)

data class ExplanationApiModel(
    val summary_title: String,
    val fraud_type: String,
    val why_flagged: String,
    val suspicious_factors: List<String> = emptyList(),
    val recommended_actions: List<String> = emptyList(),
    val token_attributions: List<TokenSpanApiModel> = emptyList(),
    val top_risk_tokens: List<String> = emptyList(),
    val top_safe_tokens: List<String> = emptyList(),
    val hindi: HindiExplanationApiModel? = null,
    val model_used: String,
    val is_ai_generated: Boolean = false
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
    val timestamp: String,
    val explanation: ExplanationApiModel? = null
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

data class UpiIntentApiModel(
    val is_upi: Boolean = true,
    val pa: String? = null,
    val pn: String? = null,
    val mc: String? = null,
    val tr: String? = null,
    val tn: String? = null,
    val am: Double? = null,
    val cu: String = "INR",
    val mode: String? = null,
    val url: String? = null
)

data class QrScanApiRequest(
    val qr_content: String
)

data class QrScanApiResponse(
    val scan_id: String,
    val payload_type: String,
    val raw_content: String,
    val parsed_upi: UpiIntentApiModel? = null,
    val classification: String,
    val risk_score: Double,
    val confidence: Double,
    val reasons: List<String> = emptyList(),
    val recommendation: String,
    val explanation: ExplanationApiModel? = null,
    val timestamp: String
)
