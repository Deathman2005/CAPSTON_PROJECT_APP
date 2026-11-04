package com.smsshield.app.service

import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import com.smsshield.app.data.local.AppDatabase
import com.smsshield.app.data.local.ScanRecordEntity
import com.smsshield.app.data.preferences.UserPreferencesRepository
import com.smsshield.domain.detector.DuplicateDetector
import com.smsshield.domain.detector.IngestionCheckResult
import com.smsshield.domain.model.ScanItem
import com.smsshield.domain.model.SecurityClassification
import com.smsshield.domain.model.ThreatCategory
import com.smsshield.domain.registry.SupportedSmsApps
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import java.util.UUID

/**
 * Opt-in NotificationListenerService for real-time security alerting.
 *
 * Responsibilities:
 * 1. Verifies notification source against SupportedSmsApps whitelist.
 * 2. Enforces user opt-in (drops all events immediately if monitoring is disabled).
 * 3. Extracts visible notification content defensively via NotificationParser.
 * 4. Deduplicates repeated notification triggers and applies rate limiting.
 * 5. Extracts URLs and evaluates heuristic security indicators off the main thread.
 * 6. Persists minimal audit metadata without ever storing or logging raw message text.
 */
class SMSNotificationListener : NotificationListenerService() {

    companion object {
        private const val TAG = "SMSNotificationListener"

        @Volatile
        var isConnected: Boolean = false
            private set

        // Expose supported SMS packages for UI and verification
        val SUPPORTED_SMS_PACKAGES = setOf(
            SupportedSmsApps.PACKAGE_GOOGLE_MESSAGES,
            SupportedSmsApps.PACKAGE_SAMSUNG_MESSAGES
        )
    }

    private val serviceJob = SupervisorJob()
    private val serviceScope = CoroutineScope(Dispatchers.Default + serviceJob)

    private val duplicateDetector = DuplicateDetector(
        deduplicationWindowMs = 60_000L,
        maxEventsPerMinute = 15
    )

    private lateinit var preferencesRepository: UserPreferencesRepository
    private lateinit var database: AppDatabase

    override fun onCreate() {
        super.onCreate()
        preferencesRepository = UserPreferencesRepository(applicationContext)
        database = AppDatabase.getDatabase(applicationContext)
        Log.i(TAG, "SMS Shield Notification Listener service created.")
    }

    override fun onListenerConnected() {
        super.onListenerConnected()
        isConnected = true
        Log.i(TAG, "SMS Shield Notification Listener connected successfully.")
    }

    override fun onListenerDisconnected() {
        super.onListenerDisconnected()
        isConnected = false
        Log.i(TAG, "SMS Shield Notification Listener disconnected.")
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
        super.onNotificationRemoved(sbn)
        // Ignored as per Section 6 Rule 2
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null) return

        val packageName = sbn.packageName

        // 1. Whitelist Check: strictly reject all non-SMS apps at listener boundary
        if (!SupportedSmsApps.isSupported(packageName)) {
            return
        }

        serviceScope.launch {
            // 2. Monitoring Preference Check: can be disabled immediately by user
            val prefs = preferencesRepository.userPreferencesFlow.first()
            if (!prefs.isMonitoringEnabled) {
                Log.d(TAG, "Monitoring is disabled in user preferences; dropping notification from $packageName.")
                return@launch
            }

            // 3. Defensive Content Parsing
            when (val parseResult = NotificationParser.parse(sbn)) {
                is NotificationParseResult.Success -> {
                    processIncomingSms(parseResult.parsed)
                }
                is NotificationParseResult.BypassedBenignOtp -> {
                    Log.d(TAG, "Benign OTP notification safely bypassed.")
                }
                is NotificationParseResult.RedactedOrEmpty -> {
                    Log.d(TAG, "Notification from $packageName contained no readable text or was redacted by OS.")
                }
                is NotificationParseResult.IgnoredUnsupportedPackage -> {
                    // Ignored
                }
            }
        }
    }

    private suspend fun processIncomingSms(parsed: ParsedSmsNotification) {
        // 4. Duplicate Detection & Rate Limiting Check
        val checkResult = duplicateDetector.checkAndRecord(
            packageName = parsed.packageName,
            sender = parsed.sender,
            messageText = parsed.messageText,
            currentTimeMs = parsed.timestamp
        )

        when (checkResult) {
            is IngestionCheckResult.Duplicate -> {
                Log.d(TAG, "Suppressed duplicate notification from ${parsed.packageName} (first seen ${checkResult.originalTimestamp})")
                return
            }
            is IngestionCheckResult.RateLimited -> {
                Log.w(TAG, "Notification rate limit reached (${checkResult.maxPerMinute}/min); throttling inspection.")
                return
            }
            is IngestionCheckResult.Accepted -> {
                // Proceed with local heuristic evaluation
            }
        }

        // 5. Safe Local Processing (Off main thread)
        val lower = parsed.messageText.lowercase()
        val reasons = mutableListOf<String>()
        var classification = SecurityClassification.SAFE
        var riskScore: Double? = 10.0
        var category = ThreatCategory.BENIGN
        var recommendation = "Message appears authentic."

        val hasUrgentThreat = lower.contains("blocked") || lower.contains("suspended") || lower.contains("deactivated") || lower.contains("immediate")
        val hasKyc = lower.contains("kyc") || lower.contains("pan") || lower.contains("aadhaar")
        val hasOtpDemand = lower.contains("otp") || lower.contains("pin") || lower.contains("password")
        val hasBank = lower.contains("bank") || lower.contains("sbi") || lower.contains("hdfc") || lower.contains("icici") || lower.contains("upi")

        val urlStrings = parsed.extractedUrls.map { it.normalized }

        if (parsed.extractedUrls.isNotEmpty() && (hasUrgentThreat || hasKyc || hasOtpDemand || hasBank)) {
            classification = SecurityClassification.MALICIOUS
            riskScore = 95.0
            category = if (hasBank) ThreatCategory.BANK_IMPERSONATION else ThreatCategory.PHISHING_URL
            if (hasUrgentThreat) reasons.add("Urgent threat of account deactivation/suspension")
            if (hasKyc) reasons.add("Unverified demand to update KYC credentials")
            reasons.add("Contains unverified web link: ${urlStrings.first()}")
            recommendation = "DO NOT click links or supply credentials. SBI/HDFC/banks never request KYC via SMS links."
        } else if (parsed.extractedUrls.isNotEmpty()) {
            classification = SecurityClassification.SUSPICIOUS
            riskScore = 65.0
            category = ThreatCategory.PHISHING_URL
            reasons.add("Message contains external web links requiring inspection")
            recommendation = "Exercise caution with unverified links."
        } else if (hasUrgentThreat && hasOtpDemand) {
            classification = SecurityClassification.SUSPICIOUS
            riskScore = 70.0
            category = ThreatCategory.OTP_THEFT
            reasons.add("Suspicious demand for verification credentials")
            recommendation = "Never share OTP or banking passwords with anyone."
        }

        val scanItem = ScanItem(
            id = UUID.randomUUID().toString(),
            timestamp = parsed.timestamp,
            classification = classification,
            riskScore = riskScore,
            confidence = 0.90,
            urlCount = parsed.extractedUrls.size,
            extractedUrls = urlStrings,
            detectionReasons = reasons,
            recommendation = recommendation,
            sourceCategory = "notification_auto"
        )

        // 6. Persistence (Zero Raw SMS Content Stored)
        try {
            database.scanRecordDao().insertScan(ScanRecordEntity.fromDomain(scanItem))
            Log.i(TAG, "Processed notification scan: classification=${classification.name}, urls=${parsed.extractedUrls.size}, score=$riskScore")
        } catch (e: Exception) {
            Log.e(TAG, "Error saving scan record: ${e.message}")
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceJob.cancel()
        Log.i(TAG, "SMS Shield Notification Listener destroyed.")
    }
}
