package com.smsshield.app.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.smsshield.app.data.local.ScanRecordDao
import com.smsshield.app.data.preferences.UserPreferencesRepository
import com.smsshield.domain.model.UserPreferences
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class SettingsViewModel(
    private val preferencesRepository: UserPreferencesRepository,
    private val scanRecordDao: ScanRecordDao
) : ViewModel() {

    val userPreferences: StateFlow<UserPreferences> = preferencesRepository.userPreferencesFlow
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = UserPreferences()
        )

    fun toggleMonitoring(enabled: Boolean) {
        viewModelScope.launch {
            preferencesRepository.setMonitoringEnabled(enabled)
        }
    }

    fun updateBackendUrl(url: String) {
        viewModelScope.launch {
            preferencesRepository.setBackendUrl(url)
        }
    }

    fun updateDataRetention(days: Int) {
        viewModelScope.launch {
            preferencesRepository.setDataRetentionDays(days)
        }
    }

    fun clearAllHistory(onCleared: () -> Unit = {}) {
        viewModelScope.launch {
            scanRecordDao.clearAllScans()
            onCleared()
        }
    }
}
