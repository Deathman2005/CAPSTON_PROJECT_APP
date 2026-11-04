package com.smsshield.app.ui.navigation

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.smsshield.app.ui.screens.home.HomeScreen
import com.smsshield.app.ui.screens.onboarding.OnboardingScreen
import com.smsshield.app.ui.screens.permission.PermissionSetupScreen
import com.smsshield.app.ui.screens.scanner.ScannerScreen
import com.smsshield.app.ui.screens.settings.SettingsScreen
import com.smsshield.app.ui.viewmodel.HomeViewModel
import com.smsshield.app.ui.viewmodel.OnboardingViewModel
import com.smsshield.app.ui.viewmodel.ScannerViewModel
import com.smsshield.app.ui.viewmodel.SettingsViewModel

@Composable
fun SMSShieldNavGraph(
    navController: NavHostController,
    hasCompletedOnboarding: Boolean,
    initialSharedText: String?,
    onboardingViewModel: OnboardingViewModel,
    homeViewModel: HomeViewModel,
    scannerViewModel: ScannerViewModel,
    settingsViewModel: SettingsViewModel
) {
    val startDestination = if (hasCompletedOnboarding) {
        Screen.Home.route
    } else {
        Screen.Onboarding.route
    }

    // Handle incoming share intent directly
    LaunchedEffect(initialSharedText) {
        if (!initialSharedText.isNullOrBlank()) {
            navController.navigate(Screen.Scanner.createRoute(initialSharedText)) {
                launchSingleTop = true
            }
        }
    }

    NavHost(
        navController = navController,
        startDestination = startDestination
    ) {
        composable(Screen.Onboarding.route) {
            OnboardingScreen(
                viewModel = onboardingViewModel,
                onNavigateNext = {
                    navController.navigate(Screen.PermissionSetup.route)
                }
            )
        }

        composable(Screen.PermissionSetup.route) {
            PermissionSetupScreen(
                onContinue = {
                    navController.navigate(Screen.Home.route) {
                        popUpTo(Screen.Onboarding.route) { inclusive = true }
                    }
                }
            )
        }

        composable(Screen.Home.route) {
            HomeScreen(
                viewModel = homeViewModel,
                onNavigateToScanner = {
                    navController.navigate(Screen.Scanner.createRoute(null))
                },
                onNavigateToSettings = {
                    navController.navigate(Screen.Settings.route)
                }
            )
        }

        composable(
            route = Screen.Scanner.route,
            arguments = listOf(
                navArgument("initialText") {
                    type = NavType.StringType
                    nullable = true
                    defaultValue = null
                }
            )
        ) { backStackEntry ->
            val textArg = backStackEntry.arguments?.getString("initialText")
            ScannerScreen(
                viewModel = scannerViewModel,
                initialSharedText = textArg ?: initialSharedText,
                onNavigateBack = {
                    navController.popBackStack()
                }
            )
        }

        composable(Screen.Settings.route) {
            SettingsScreen(
                viewModel = settingsViewModel,
                onNavigateBack = {
                    navController.popBackStack()
                }
            )
        }
    }
}
