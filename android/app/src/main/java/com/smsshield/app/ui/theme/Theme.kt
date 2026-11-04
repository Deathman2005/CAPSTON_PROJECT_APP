package com.smsshield.app.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColorScheme = darkColorScheme(
    primary = ShieldCyan,
    onPrimary = Color.Black,
    secondary = ShieldSafe,
    background = ShieldDarkBg,
    surface = ShieldCardBg,
    onBackground = Color.White,
    onSurface = Color.White,
    error = ShieldDanger
)

@Composable
fun SMSShieldTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        typography = Typography,
        content = content
    )
}
