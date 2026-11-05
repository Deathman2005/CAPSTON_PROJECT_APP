package com.smsshield.app.data.repository

import android.content.Context
import android.util.Log
import com.smsshield.app.data.local.AppDatabase
import com.smsshield.app.data.local.ScanRecordEntity
import com.smsshield.app.data.preferences.UserPreferencesRepository
import com.smsshield.app.data.remote.ApiClient
import com.smsshield.domain.model.*
import com.smsshield.domain.parser.UrlExtractor
import kotlinx.coroutines.flow.first
import java.util.UUID

/**
 * Central repository managing online backend AI scans, offline fallback inspection,
 * and local Room database persistence.
 */
class ScanRepository(
    private val context: Context,
    private val database: AppDatabase = AppDatabase.getDatabase(context),
    private val preferencesRepository: UserPreferencesRepository = UserPreferencesRepository(context)
) {

    companion object {
        private const val TAG = "ScanRepository"
    }

    suspend fun scanMessage(
        messageText: String,
        sourceType: String = "manual_paste",
        sourcePackage: String? = null
    ): Result<ScanItem> {
        val prefs = preferencesRepository.userPreferencesFlow.first()
        val baseUrl = prefs.backendBaseUrl.ifBlank { ApiClient.DEFAULT_BASE_URL }

        return try {
            val api = ApiClient.getApi(baseUrl)
            val response = api.scanMessage(
                MessageScanApiRequest(
                    message_text = messageText,
                    source_type = sourceType,
                    source_package = sourcePackage
                )
            )

            val classification = try {
                SecurityClassification.valueOf(response.classification.uppercase())
            } catch (e: Exception) {
                SecurityClassification.UNKNOWN
            }

            val item = ScanItem(
                id = response.scan_id,
                timestamp = System.currentTimeMillis(),
                classification = classification,
                riskScore = response.risk_score,
                confidence = response.confidence,
                urlCount = response.extracted_urls.size,
                extractedUrls = response.extracted_urls,
                detectionReasons = response.reasons,
                recommendation = response.recommendation,
                sourceCategory = sourceType
            )

            // Persist to local Room database (STRICT PRIVACY: zero raw SMS text)
            database.scanRecordDao().insertScan(ScanRecordEntity.fromDomain(item))
            Log.i(TAG, "Online scan completed successfully: ${item.classification} (Score: ${item.riskScore})")
            Result.success(item)

        } catch (e: Exception) {
            Log.w(TAG, "Backend scan failed ($e); executing local defensive fallback assessment.")
            val fallbackItem = evaluateOfflineFallback(messageText, sourceType)
            database.scanRecordDao().insertScan(ScanRecordEntity.fromDomain(fallbackItem))
            Result.success(fallbackItem)
        }
    }

    suspend fun scanUrl(url: String): Result<UrlScanApiResponse> {
        val prefs = preferencesRepository.userPreferencesFlow.first()
        val baseUrl = prefs.backendBaseUrl.ifBlank { ApiClient.DEFAULT_BASE_URL }

        return try {
            val api = ApiClient.getApi(baseUrl)
            val response = api.scanUrl(UrlScanApiRequest(url = url))

            val classification = when (response.final_url_classification.lowercase()) {
                "malicious" -> SecurityClassification.MALICIOUS
                "suspicious" -> SecurityClassification.SUSPICIOUS
                "benign", "safe" -> SecurityClassification.SAFE
                else -> SecurityClassification.UNKNOWN
            }

            val item = ScanItem(
                id = response.scan_id,
                timestamp = System.currentTimeMillis(),
                classification = classification,
                riskScore = response.risk_score,
                confidence = 0.90,
                urlCount = 1,
                extractedUrls = listOf(response.normalized_url),
                detectionReasons = response.evidence,
                recommendation = response.recommendation,
                sourceCategory = "url_inspect"
            )
            database.scanRecordDao().insertScan(ScanRecordEntity.fromDomain(item))
            Result.success(response)
        } catch (e: Exception) {
            Log.e(TAG, "URL scan failed: ${e.message}")
            Result.failure(e)
        }
    }

    private fun evaluateOfflineFallback(text: String, sourceType: String): ScanItem {
        val lower = text.lowercase()
        val extracted = UrlExtractor.extractUrls(text)
        val urls = extracted.map { it.normalized }

        val hasUrgent = lower.contains("blocked") || lower.contains("suspended") || lower.contains("immediate") || lower.contains("penalty")
        val hasKyc = lower.contains("kyc") || lower.contains("pan") || lower.contains("aadhaar")
        val hasOtp = lower.contains("otp") || lower.contains("pin") || lower.contains("password")
        val hasBank = lower.contains("sbi") || lower.contains("hdfc") || lower.contains("icici") || lower.contains("bank") || lower.contains("upi")

        val reasons = mutableListOf<String>()
        val classification: SecurityClassification
        val riskScore: Double
        val recommendation: String

        if (urls.isNotEmpty() && (hasUrgent || hasKyc || hasOtp || hasBank)) {
            classification = SecurityClassification.MALICIOUS
            riskScore = 94.0
            if (hasUrgent) reasons.add("Urgent threat of account deactivation/suspension")
            if (hasKyc) reasons.add("Unverified demand to update KYC credentials")
            reasons.add("Contains unverified link: ${urls.first()}")
            recommendation = "[Offline Assessment] HIGH-RISK SCAM: Do not open links or enter credentials."
        } else if (urls.isNotEmpty()) {
            classification = SecurityClassification.SUSPICIOUS
            riskScore = 65.0
            reasons.add("Contains unverified web link requiring analysis")
            recommendation = "[Offline Assessment] Exercise caution with unverified links."
        } else if (hasUrgent && hasOtp) {
            classification = SecurityClassification.SUSPICIOUS
            riskScore = 70.0
            reasons.add("Suspicious demand for verification codes")
            recommendation = "[Offline Assessment] Never share OTP or banking passwords."
        } else {
            classification = SecurityClassification.SAFE
            riskScore = 12.0
            recommendation = "[Offline Assessment] Message appears authentic."
        }

        return ScanItem(
            id = UUID.randomUUID().toString(),
            timestamp = System.currentTimeMillis(),
            classification = classification,
            riskScore = riskScore,
            confidence = 0.70,
            urlCount = urls.size,
            extractedUrls = urls,
            detectionReasons = reasons,
            recommendation = recommendation,
            sourceCategory = sourceType
        )
    }
}

