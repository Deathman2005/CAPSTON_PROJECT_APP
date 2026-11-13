package com.smsshield.app.util

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import androidx.core.app.NotificationManagerCompat
import com.smsshield.app.service.SMSNotificationListener

object PermissionUtils {

    /**
     * Checks if the app currently possesses the NotificationListener permission.
     * Uses multiple fallback strategies for maximum reliability across custom Android vendor ROMs (MIUI, HyperOS, etc.).
     */
    fun isNotificationListenerEnabled(context: Context): Boolean {
        // 1. Direct runtime service connection check
        if (SMSNotificationListener.isConnected) {
            return true
        }

        // 2. AndroidX standard check
        try {
            val enabledPackages = NotificationManagerCompat.getEnabledListenerPackages(context)
            if (enabledPackages.contains(context.packageName)) {
                return true
            }
        } catch (_: Exception) { }

        // 3. Fallback to direct Secure Settings inspection
        return try {
            val flat = Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners")
            flat != null && flat.contains(context.packageName)
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Returns an intent to navigate the user directly to the Android Notification Access settings screen.
     */
    fun createNotificationListenerSettingsIntent(): Intent {
        return Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
    }

    /**
     * Determines whether the host device runs Xiaomi MIUI or HyperOS.
     */
    fun isXiaomiDevice(): Boolean {
        val man = Build.MANUFACTURER.orEmpty().lowercase()
        val brand = Build.BRAND.orEmpty().lowercase()
        return man.contains("xiaomi") || man.contains("redmi") || man.contains("poco") ||
               brand.contains("xiaomi") || brand.contains("redmi") || brand.contains("poco")
    }

    /**
     * Navigates directly to Xiaomi Autostart settings to prevent MIUI/HyperOS from killing the listener.
     */
    fun openXiaomiAutostart(context: Context): Boolean {
        val intents = listOf(
            Intent().setComponent(ComponentName("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity")),
            Intent("miui.intent.action.OP_AUTO_START").addCategory(Intent.CATEGORY_DEFAULT),
            Intent().setComponent(ComponentName("com.miui.securitycenter", "com.miui.powerkeeper.ui.HiddenAppsConfigActivity"))
        )
        for (intent in intents) {
            try {
                intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
                context.startActivity(intent)
                return true
            } catch (_: Exception) { }
        }
        return false
    }

    /**
     * Requests ignoring battery optimizations or opens App details settings.
     */
    fun requestIgnoreBatteryOptimizations(context: Context): Boolean {
        try {
            val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            if (pm != null && !pm.isIgnoringBatteryOptimizations(context.packageName)) {
                val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = Uri.parse("package:${context.packageName}")
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
                context.startActivity(intent)
                return true
            }
        } catch (_: Exception) { }

        // Fallback to app info details
        return try {
            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = Uri.parse("package:${context.packageName}")
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            }
            context.startActivity(intent)
            true
        } catch (_: Exception) {
            false
        }
    }
}
