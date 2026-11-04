package com.smsshield.app.util

import android.content.Context
import android.content.Intent
import android.provider.Settings
import androidx.core.app.NotificationManagerCompat

object PermissionUtils {

    /**
     * Checks if the app currently possesses the NotificationListener permission.
     */
    fun isNotificationListenerEnabled(context: Context): Boolean {
        val enabledPackages = NotificationManagerCompat.getEnabledListenerPackages(context)
        return enabledPackages.contains(context.packageName)
    }

    /**
     * Returns an intent to navigate the user directly to the Android Notification Access settings screen.
     */
    fun createNotificationListenerSettingsIntent(): Intent {
        return Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
    }
}
