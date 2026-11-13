package com.smsshield.app.ui.viewmodel

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.smsshield.app.data.repository.ScanRepository
import com.smsshield.app.service.AlertNotificationManager
import com.smsshield.domain.model.ScanItem
import com.smsshield.domain.model.SecurityClassification
import com.smsshield.domain.parser.UrlExtractor
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

sealed class ScanUiState {
    object Idle : ScanUiState()
    object Loading : ScanUiState()
    data class Success(val result: ScanItem) : ScanUiState()
    data class Error(val message: String) : ScanUiState()
}

enum class ScanMode {
    SMS,
    QR
}

class ScannerViewModel(
    private val scanRepository: ScanRepository,
    private val context: Context? = null
) : ViewModel() {

    private val _scanMode = MutableStateFlow(ScanMode.SMS)
    val scanMode: StateFlow<ScanMode> = _scanMode.asStateFlow()

    private val _messageText = MutableStateFlow("")
    val messageText: StateFlow<String> = _messageText.asStateFlow()

    private val _qrText = MutableStateFlow("")
    val qrText: StateFlow<String> = _qrText.asStateFlow()

    private val _extractedUrls = MutableStateFlow<List<String>>(emptyList())
    val extractedUrls: StateFlow<List<String>> = _extractedUrls.asStateFlow()

    private val _scanState = MutableStateFlow<ScanUiState>(ScanUiState.Idle)
    val scanState: StateFlow<ScanUiState> = _scanState.asStateFlow()

    fun setScanMode(mode: ScanMode) {
        _scanMode.value = mode
        if (_scanState.value is ScanUiState.Error) {
            _scanState.value = ScanUiState.Idle
        }
    }

    fun updateMessageText(text: String) {
        _messageText.value = text
        _extractedUrls.value = UrlExtractor.extractUrls(text)
        if (_scanState.value is ScanUiState.Error) {
            _scanState.value = ScanUiState.Idle
        }
    }

    fun updateQrText(text: String) {
        _qrText.value = text
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

            val result = scanRepository.scanMessage(
                messageText = text,
                sourceType = sourceCategory
            )

            result.onSuccess { item ->
                _scanState.value = ScanUiState.Success(item)
                context?.let { ctx ->
                    AlertNotificationManager.showSecurityAlert(ctx, item, notifyIfSafe = true)
                }
            }.onFailure { err ->
                _scanState.value = ScanUiState.Error(err.message ?: "Failed to analyze message.")
            }
        }
    }

    fun scanUrl(url: String) {
        val trimmed = url.trim()
        if (trimmed.isBlank()) {
            _scanState.value = ScanUiState.Error("Please enter a valid URL to analyze.")
            return
        }

        viewModelScope.launch {
            _scanState.value = ScanUiState.Loading

            val result = scanRepository.scanUrl(trimmed)
            result.onSuccess { urlResponse ->
                val classification = when (urlResponse.final_url_classification.lowercase()) {
                    "malicious" -> SecurityClassification.MALICIOUS
                    "suspicious" -> SecurityClassification.SUSPICIOUS
                    "benign", "safe" -> SecurityClassification.SAFE
                    else -> SecurityClassification.UNKNOWN
                }
                val item = ScanItem(
                    id = urlResponse.scan_id,
                    timestamp = System.currentTimeMillis(),
                    classification = classification,
                    riskScore = urlResponse.risk_score,
                    confidence = 0.90,
                    urlCount = 1,
                    extractedUrls = listOf(urlResponse.normalized_url),
                    detectionReasons = urlResponse.evidence,
                    recommendation = urlResponse.recommendation,
                    sourceCategory = "manual_url",
                    scannedText = trimmed,
                    payloadType = "url"
                )
                _scanState.value = ScanUiState.Success(item)
                context?.let { ctx ->
                    AlertNotificationManager.showSecurityAlert(ctx, item, notifyIfSafe = true)
                }
            }.onFailure { err ->
                _scanState.value = ScanUiState.Error(err.message ?: "Failed to analyze URL.")
            }
        }
    }

    fun scanQr(qrContent: String) {
        val trimmed = qrContent.trim()
        if (trimmed.isBlank()) {
            _scanState.value = ScanUiState.Error("Please enter or paste QR code content (e.g. upi://pay?...).")
            return
        }

        viewModelScope.launch {
            _scanState.value = ScanUiState.Loading

            val result = scanRepository.scanQr(trimmed)
            result.onSuccess { item ->
                _scanState.value = ScanUiState.Success(item)
                context?.let { ctx ->
                    AlertNotificationManager.showSecurityAlert(ctx, item, notifyIfSafe = true)
                }
            }.onFailure { err ->
                _scanState.value = ScanUiState.Error(err.message ?: "Failed to analyze QR code.")
            }
        }
    }

    fun clear() {
        _messageText.value = ""
        _qrText.value = ""
        _extractedUrls.value = emptyList()
        _scanState.value = ScanUiState.Idle
    }
}
