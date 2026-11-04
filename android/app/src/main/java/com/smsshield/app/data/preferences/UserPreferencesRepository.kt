package com.smsshield.app.data.preferences

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.*
import androidx.datastore.preferences.preferencesDataStore
import com.smsshield.domain.model.UserPreferences
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map
import java.io.IOException

val Context.userDataStore: DataStore<Preferences> by preferencesDataStore(name = "user_preferences")

class UserPreferencesRepository(private val context: Context) {

    companion object {
        val KEY_MONITORING_ENABLED = booleanPreferencesKey("is_monitoring_enabled")
        val KEY_ONBOARDING_COMPLETED = booleanPreferencesKey("has_completed_onboarding")
        val KEY_BACKEND_URL = stringPreferencesKey("backend_url")
        val KEY_DATA_RETENTION_DAYS = intPreferencesKey("data_retention_days")

        const val DEFAULT_BACKEND_URL = "http://10.0.2.2:8000"
        const val DEFAULT_RETENTION_DAYS = 30
    }

    val userPreferencesFlow: Flow<UserPreferences> = context.userDataStore.data
        .catch { exception ->
            if (exception is IOException) {
                emit(emptyPreferences())
            } else {
                throw exception
            }
        }
        .map { preferences ->
            UserPreferences(
                isMonitoringEnabled = preferences[KEY_MONITORING_ENABLED] ?: false,
                hasCompletedOnboarding = preferences[KEY_ONBOARDING_COMPLETED] ?: false,
                backendUrl = preferences[KEY_BACKEND_URL] ?: DEFAULT_BACKEND_URL,
                dataRetentionDays = preferences[KEY_DATA_RETENTION_DAYS] ?: DEFAULT_RETENTION_DAYS
            )
        }

    suspend fun setMonitoringEnabled(enabled: Boolean) {
        context.userDataStore.edit { preferences ->
            preferences[KEY_MONITORING_ENABLED] = enabled
        }
    }

    suspend fun setOnboardingCompleted(completed: Boolean) {
        context.userDataStore.edit { preferences ->
            preferences[KEY_ONBOARDING_COMPLETED] = completed
        }
    }

    suspend fun setBackendUrl(url: String) {
        context.userDataStore.edit { preferences ->
            preferences[KEY_BACKEND_URL] = url
        }
    }

    suspend fun setDataRetentionDays(days: Int) {
        context.userDataStore.edit { preferences ->
            preferences[KEY_DATA_RETENTION_DAYS] = days
        }
    }
}

