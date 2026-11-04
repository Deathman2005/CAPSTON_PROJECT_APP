package com.smsshield.app.ui.screens.permission

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.NotificationsActive
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.LifecycleResumeEffect
import com.smsshield.app.ui.theme.*
import com.smsshield.app.util.PermissionUtils

@Composable
fun PermissionSetupScreen(
    onContinue: () -> Unit
) {
    val context = LocalContext.current
    var isPermissionGranted by remember { mutableStateOf(PermissionUtils.isNotificationListenerEnabled(context)) }

    // Re-check permission whenever the activity resumes (e.g. returning from Android Settings)
    LifecycleResumeEffect(Unit) {
        isPermissionGranted = PermissionUtils.isNotificationListenerEnabled(context)
        onPauseOrDispose { }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(ShieldDarkBg)
            .padding(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(28.dp))

        Surface(
            shape = RoundedCornerShape(16.dp),
            color = if (isPermissionGranted) ShieldSafe.copy(alpha = 0.15f) else ShieldWarning.copy(alpha = 0.15f),
            border = androidx.compose.foundation.BorderStroke(
                1.dp,
                if (isPermissionGranted) ShieldSafe else ShieldWarning
            ),
            modifier = Modifier.size(68.dp)
        ) {
            Box(contentAlignment = Alignment.Center) {
                Icon(
                    imageVector = Icons.Default.NotificationsActive,
                    contentDescription = null,
                    tint = if (isPermissionGranted) ShieldSafe else ShieldWarning,
                    modifier = Modifier.size(36.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Notification Access Setup",
            style = MaterialTheme.typography.titleLarge,
            color = Color.White,
            fontWeight = FontWeight.Bold
        )

        Text(
            text = "Enables real-time scam alerting for incoming SMS notifications",
            fontSize = 13.sp,
            color = Color.LightGray,
            modifier = Modifier.padding(top = 4.dp)
        )

        Spacer(modifier = Modifier.height(24.dp))

        // Status Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = ShieldCardBg),
            shape = RoundedCornerShape(12.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Permission Status", fontSize = 14.sp, color = Color.White, fontWeight = FontWeight.Medium)
                    Surface(
                        color = if (isPermissionGranted) ShieldSafe.copy(alpha = 0.2f) else ShieldWarning.copy(alpha = 0.2f),
                        shape = RoundedCornerShape(4.dp),
                        border = androidx.compose.foundation.BorderStroke(
                            1.dp,
                            if (isPermissionGranted) ShieldSafe else ShieldWarning
                        )
                    ) {
                        Text(
                            text = if (isPermissionGranted) "GRANTED" else "NOT GRANTED",
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (isPermissionGranted) ShieldSafe else ShieldWarning
                        )
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    text = if (isPermissionGranted) {
                        "Notification access is verified. Incoming messages from Google Messages and Samsung Messages can now be analyzed."
                    } else {
                        "SMS Shield needs Notification Access to alert you in real-time when a suspicious SMS arrives. We strictly monitor only supported SMS apps."
                    },
                    fontSize = 12.sp,
                    color = Color.LightGray,
                    lineHeight = 16.sp
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Permission Button (Open Settings)
        if (!isPermissionGranted) {
            Button(
                onClick = {
                    val intent = PermissionUtils.createNotificationListenerSettingsIntent()
                    context.startActivity(intent)
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                colors = ButtonDefaults.buttonColors(containerColor = ShieldCyan),
                shape = RoundedCornerShape(10.dp)
            ) {
                Text("Open Notification Settings", color = Color.Black, fontWeight = FontWeight.Bold, fontSize = 14.sp)
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Note about manual scanning availability
        Surface(
            color = ShieldCardBg,
            shape = RoundedCornerShape(10.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.Top) {
                Icon(Icons.Default.CheckCircle, contentDescription = null, tint = ShieldSafe, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Manual scanning via copy-paste and Android Share Sheet is always available, even if you choose not to grant notification access.",
                    fontSize = 11.sp,
                    color = Color.LightGray,
                    lineHeight = 15.sp
                )
            }
        }

        Spacer(modifier = Modifier.weight(1f))

        // Continue Button
        Button(
            onClick = onContinue,
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = if (isPermissionGranted) ShieldSafe else ShieldCyan
            ),
            shape = RoundedCornerShape(10.dp)
        ) {
            Text(
                text = if (isPermissionGranted) "Continue to Home" else "Skip & Continue to Home",
                color = Color.Black,
                fontWeight = FontWeight.Bold,
                fontSize = 14.sp
            )
        }

        Spacer(modifier = Modifier.height(24.dp))
    }
}
