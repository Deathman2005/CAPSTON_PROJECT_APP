package com.smsshield.app.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.smsshield.app.data.local.ScanRecordDao
import com.smsshield.app.data.preferences.UserPreferencesRepository
import com.smsshield.domain.model.ScanItem
import kotlinx.coroutines.flow.*

data class HomeUiState(
    val isMonitoringEnabled: Boolean = false,
    val isListenerPermissionGranted: Boolean = false,
    val totalScans: Int = 0,
    val safeCount: Int = 0,
    val suspiciousCount: Int = 0,
    val maliciousCount: Int = 0,
    val recentScans: List<ScanItem> = emptyList()
)

class HomeViewModel(
    private val preferencesRepository: UserPreferencesRepository,
    private val scanRecordDao: ScanRecordDao
) : ViewModel() {

    private val _isPermissionGranted = MutableStateFlow(false)

    private val _countsFlow = combine(
        scanRecordDao.getTotalScanCount().catch { emit(0) },
        scanRecordDao.getScanCountByClassification("SAFE").catch { emit(0) },
        scanRecordDao.getScanCountByClassification("SUSPICIOUS").catch { emit(0) },
        scanRecordDao.getScanCountByClassification("MALICIOUS").catch { emit(0) }
    ) { total, safe, suspicious, malicious ->
        listOf(total, safe, suspicious, malicious)
    }

    val uiState: StateFlow<HomeUiState> = combine(
        preferencesRepository.userPreferencesFlow,
        _isPermissionGranted,
        _countsFlow,
        scanRecordDao.getRecentScans(10).catch { emit(emptyList()) }
    ) { prefs, permGranted, counts, recent ->
        HomeUiState(
            isMonitoringEnabled = prefs.isMonitoringEnabled,
            isListenerPermissionGranted = permGranted,
            totalScans = counts[0],
            safeCount = counts[1],
            suspiciousCount = counts[2],
            maliciousCount = counts[3],
            recentScans = recent.map { it.toDomain() }
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = HomeUiState()
    )

    fun updatePermissionStatus(isGranted: Boolean) {
        _isPermissionGranted.value = isGranted
    }
}

