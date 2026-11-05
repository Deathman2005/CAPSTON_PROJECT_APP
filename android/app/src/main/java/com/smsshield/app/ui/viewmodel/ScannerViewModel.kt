package com.smsshield.app.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.smsshield.app.data.repository.ScanRepository
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

class ScannerViewModel(
    private val scanRepository: ScanRepository
) : ViewModel() {

    private val _messageText = MutableStateFlow("")
    val messageText: StateFlow<String> = _messageText.asStateFlow()

    private val _extractedUrls = MutableStateFlow<List<String>>(emptyList())
    val extractedUrls: StateFlow<List<String>> = _extractedUrls.asStateFlow()

    private val _scanState = MutableStateFlow<ScanUiState>(ScanUiState.Idle)
    val scanState: StateFlow<ScanUiState> = _scanState.asStateFlow()

    fun updateMessageText(text: String) {
        _messageText.value = text
        val extracted = UrlExtractor.extractUrls(text)
        _extractedUrls.value = extracted.map { it.normalized }
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
                    sourceCategory = "manual_url"
                )
                _scanState.value = ScanUiState.Success(item)
            }.onFailure { err ->
                _scanState.value = ScanUiState.Error(err.message ?: "Failed to analyze URL.")
            }
        }
    }

    fun clear() {
        _messageText.value = ""
        _extractedUrls.value = emptyList()
        _scanState.value = ScanUiState.Idle
    }
}
