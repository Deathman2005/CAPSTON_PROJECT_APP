package com.smsshield.app.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import com.smsshield.app.MainActivity
import com.smsshield.domain.alert.AlertDecisionEngine
import com.smsshield.domain.alert.AlertPriority
import com.smsshield.domain.model.ScanItem

/**
 * Handles creation and dispatch of high-priority security warning notifications.
 */
object AlertNotificationManager {

    private const val TAG = "AlertNotificationManager"
    const val CHANNEL_ID = "SMS_SHIELD_SECURITY_ALERTS"
    private const val CHANNEL_NAME = "Security Scam Alerts"
    private const val CHANNEL_DESCRIPTION = "High-priority notifications when phishing, scams, or malicious URLs are detected"

    fun createNotificationChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = CHANNEL_DESCRIPTION
                enableVibration(true)
                setShowBadge(true)
                lockscreenVisibility = NotificationCompat.VISIBILITY_PUBLIC
            }

            val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            manager?.createNotificationChannel(channel)
            Log.d(TAG, "Notification channel $CHANNEL_ID registered.")
        }
    }

    fun showSecurityAlert(context: Context, scan: ScanItem) {
        createNotificationChannel(context)
        val payload = AlertDecisionEngine.evaluate(scan)
        if (!payload.shouldAlert) {
            return
        }

        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("EXTRA_SCAN_ID", scan.id)
            putExtra("EXTRA_CLASSIFICATION", scan.classification.name)
            putExtra("EXTRA_RISK_SCORE", scan.riskScore ?: 0.0)
        }

        val pendingIntent = PendingIntent.getActivity(
            context,
            scan.id.hashCode(),
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notificationPriority = when (payload.priority) {
            AlertPriority.HIGH -> NotificationCompat.PRIORITY_HIGH
            AlertPriority.DEFAULT -> NotificationCompat.PRIORITY_DEFAULT
            AlertPriority.NONE -> NotificationCompat.PRIORITY_LOW
        }

        val builder = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(payload.title)
            .setContentText(payload.body)
            .setStyle(NotificationCompat.BigTextStyle().bigText("${payload.body}\n\nAction: ${payload.recommendation}"))
            .setPriority(notificationPriority)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)

        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
        try {
            manager?.notify(scan.id.hashCode(), builder.build())
            Log.i(TAG, "Dispatched security warning notification for scanId: ${scan.id}")
        } catch (e: SecurityException) {
            Log.w(TAG, "Unable to post notification: permission not granted ($e)")
        }
    }
}
