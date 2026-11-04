package com.smsshield.app.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.smsshield.app.data.local.ScanRecordDao
import com.smsshield.app.data.local.ScanRecordEntity
import com.smsshield.domain.model.RiskAssessment
import com.smsshield.domain.model.ScanItem
import com.smsshield.domain.model.SecurityClassification
import com.smsshield.domain.model.ThreatCategory
import com.smsshield.domain.parser.UrlExtractor
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.UUID

sealed class ScanUiState {
    object Idle : ScanUiState()
    object Loading : ScanUiState()
    data class Success(val result: ScanItem) : ScanUiState()
    data class Error(val message: String) : ScanUiState()
}

class ScannerViewModel(
    private val scanRecordDao: ScanRecordDao
) : ViewModel() {

    private val _messageText = MutableStateFlow("")
    val messageText: StateFlow<String> = _messageText.asStateFlow()

    private val _extractedUrls = MutableStateFlow<List<String>>(emptyList())
    val extractedUrls: StateFlow<List<String>> = _extractedUrls.asStateFlow()

    private val _scanState = MutableStateFlow<ScanUiState>(ScanUiState.Idle)
    val scanState: StateFlow<ScanUiState> = _scanState.asStateFlow()

    fun updateMessageText(text: String) {
        _messageText.value = text
        _extractedUrls.value = UrlExtractor.extractUrls(text)
        if (_scanState.value is ScanUiState.Error) {
            _scanState.value = ScanUiState.Idle
        }
    }

    fun scanMessage(sourceCategory: String = "manual_input") {
        val text = _messageText.value.trim()
        if (text.isBlank()) {
            _scanState.value = ScanUiState.Error("Please enter or paste message text to analyze.")
            return
        }

        viewModelScope.launch {
            _scanState.value = ScanUiState.Loading

            // Simulate parsing and initial rule assessment latency (500ms)
            delay(500)

            val urls = UrlExtractor.extractUrls(text)
            val lowerText = text.lowercase()

            // Heuristic detection rules
            val reasons = mutableListOf<String>()
            var classification = SecurityClassification.SAFE
            var riskScore: Double? = 12.0
            var category = ThreatCategory.BENIGN
            var recommendation = "Message appears authentic. Standard security vigilance applies."

            val hasUrgentThreat = lowerText.contains("blocked") || lowerText.contains("suspended") || lowerText.contains("immediate") || lowerText.contains("deactivated")
            val hasKyc = lowerText.contains("kyc") || lowerText.contains("pan") || lowerText.contains("aadhaar")
            val hasOtpRequest = lowerText.contains("otp") || lowerText.contains("pin") || lowerText.contains("password")
            val hasBank = lowerText.contains("sbi") || lowerText.contains("hdfc") || lowerText.contains("icici") || lowerText.contains("bank") || lowerText.contains("upi")

            if (urls.isNotEmpty() && (hasUrgentThreat || hasKyc || hasOtpRequest || hasBank)) {
                classification = SecurityClassification.MALICIOUS
                riskScore = 94.5
                category = if (hasBank) ThreatCategory.BANK_IMPERSONATION else ThreatCategory.PHISHING_URL
                if (hasUrgentThreat) reasons.add("Urgent threat of account deactivation/suspension")
                if (hasKyc) reasons.add("Unverified demand to update KYC credentials")
                if (urls.isNotEmpty()) reasons.add("Contains unverified web link: ${urls.first()}")
                recommendation = "DO NOT click any links. Never provide OTP, PIN, or credentials to unverified senders."
            } else if (urls.isNotEmpty()) {
                classification = SecurityClassification.SUSPICIOUS
                riskScore = 65.0
                category = ThreatCategory.PHISHING_URL
                reasons.add("Message contains external URL requiring threat intelligence verification")
                recommendation = "Exercise caution when visiting external links."
            } else if (hasUrgentThreat && hasOtpRequest) {
                classification = SecurityClassification.SUSPICIOUS
                riskScore = 70.0
                category = ThreatCategory.OTP_THEFT
                reasons.add("Suspicious request related to verification credentials")
                recommendation = "Never disclose one-time passwords (OTPs) to anyone."
            }

            val scanItem = ScanItem(
                id = UUID.randomUUID().toString(),
                timestamp = System.currentTimeMillis(),
                classification = classification,
                riskScore = riskScore,
                confidence = 0.91,
                urlCount = urls.size,
                extractedUrls = urls,
                detectionReasons = reasons,
                recommendation = recommendation,
                sourceCategory = sourceCategory
            )

            // Persist scan metadata to Room (strictly zero raw SMS stored)
            try {
                scanRecordDao.insertScan(ScanRecordEntity.fromDomain(scanItem))
            } catch (e: Exception) {
                // Defensive logging
            }

            _scanState.value = ScanUiState.Success(scanItem)
        }
    }

    fun clear() {
        _messageText.value = ""
        _extractedUrls.value = emptyList()
        _scanState.value = ScanUiState.Idle
    }
}

