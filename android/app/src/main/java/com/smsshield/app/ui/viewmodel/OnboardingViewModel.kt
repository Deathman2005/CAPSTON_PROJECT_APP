package com.smsshield.app.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.smsshield.app.data.preferences.UserPreferencesRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class OnboardingViewModel(
    private val preferencesRepository: UserPreferencesRepository
) : ViewModel() {

    private val _optInChecked = MutableStateFlow(false)
    val optInChecked: StateFlow<Boolean> = _optInChecked.asStateFlow()

    fun setOptIn(checked: Boolean) {
        _optInChecked.value = checked
    }

    fun completeOnboarding(onSuccess: () -> Unit) {
        viewModelScope.launch {
            preferencesRepository.setOnboardingCompleted(true)
            preferencesRepository.setMonitoringEnabled(_optInChecked.value)
            onSuccess()
        }
    }
}

