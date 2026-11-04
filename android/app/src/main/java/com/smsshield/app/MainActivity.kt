package com.smsshield.app

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.navigation.compose.rememberNavController
import com.smsshield.app.data.local.AppDatabase
import com.smsshield.app.data.preferences.UserPreferencesRepository
import com.smsshield.app.ui.navigation.SMSShieldNavGraph
import com.smsshield.app.ui.theme.SMSShieldTheme
import com.smsshield.app.ui.theme.ShieldCyan
import com.smsshield.app.ui.viewmodel.HomeViewModel
import com.smsshield.app.ui.viewmodel.OnboardingViewModel
import com.smsshield.app.ui.viewmodel.ScannerViewModel
import com.smsshield.app.ui.viewmodel.SettingsViewModel

class MainActivity : ComponentActivity() {

    private var sharedTextState = mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        sharedTextState.value = extractShareIntentText(intent)

        val preferencesRepository = UserPreferencesRepository(applicationContext)
        val database = AppDatabase.getDatabase(applicationContext)
        val scanRecordDao = database.scanRecordDao()

        val onboardingViewModel = OnboardingViewModel(preferencesRepository)
        val homeViewModel = HomeViewModel(preferencesRepository, scanRecordDao)
        val scannerViewModel = ScannerViewModel(scanRecordDao)
        val settingsViewModel = SettingsViewModel(preferencesRepository, scanRecordDao)

        setContent {
            SMSShieldTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val userPreferences by preferencesRepository.userPreferencesFlow.collectAsState(initial = null)

                    if (userPreferences == null) {
                        // Splash loading while DataStore preferences load
                        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                            CircularProgressIndicator(color = ShieldCyan)
                        }
                    } else {
                        val navController = rememberNavController()
                        val sharedText by sharedTextState

                        SMSShieldNavGraph(
                            navController = navController,
                            hasCompletedOnboarding = userPreferences!!.hasCompletedOnboarding,
                            initialSharedText = sharedText,
                            onboardingViewModel = onboardingViewModel,
                            homeViewModel = homeViewModel,
                            scannerViewModel = scannerViewModel,
                            settingsViewModel = settingsViewModel
                        )
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        val extracted = extractShareIntentText(intent)
        if (extracted != null) {
            sharedTextState.value = extracted
        }
    }

    private fun extractShareIntentText(intent: Intent?): String? {
        if (intent?.action == Intent.ACTION_SEND && intent.type == "text/plain") {
            return intent.getStringExtra(Intent.EXTRA_TEXT)
        }
        return null
    }
}
