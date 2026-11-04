package com.smsshield.app.service

import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log

/**
 * Opt-in NotificationListenerService for real-time security alerting.
 * Strictly filters incoming notifications against whitelisted SMS applications.
 */
class SMSNotificationListener : NotificationListenerService() {

    companion object {
        private const val TAG = "SMSNotificationListener"

        // Approved SMS application packages
        val SUPPORTED_SMS_PACKAGES = setOf(
            "com.google.android.apps.messaging", // Google Messages
            "com.samsung.android.messaging"       // Samsung Messages
        )

        @Volatile
        var isConnected: Boolean = false
            private set
    }

    override fun onListenerConnected() {
        super.onListenerConnected()
        isConnected = true
        Log.i(TAG, "SMS Shield Notification Listener connected successfully.")
    }

    override fun onListenerDisconnected() {
        super.onListenerDisconnected()
        isConnected = false
        Log.i(TAG, "SMS Shield Notification Listener disconnected.")
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null) return

        val packageName = sbn.packageName
        if (!SUPPORTED_SMS_PACKAGES.contains(packageName)) {
            // Strictly drop all unrelated applications (WhatsApp, Banking, Email, etc.)
            return
        }

        // Notification parsing will be integrated in Phase 2
        Log.d(TAG, "Detected notification from supported SMS package: $packageName")
    }
}
