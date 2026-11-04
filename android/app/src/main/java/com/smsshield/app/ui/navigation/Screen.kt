package com.smsshield.app.ui.navigation

import android.net.Uri

sealed class Screen(val route: String) {
    object Onboarding : Screen("onboarding")
    object PermissionSetup : Screen("permission_setup")
    object Home : Screen("home")
    object Scanner : Screen("scanner?initialText={initialText}") {
        fun createRoute(initialText: String? = null): String {
            return if (initialText.isNullOrBlank()) {
                "scanner"
            } else {
                "scanner?initialText=${Uri.encode(initialText)}"
            }
        }
    }
    object Settings : Screen("settings")
}
