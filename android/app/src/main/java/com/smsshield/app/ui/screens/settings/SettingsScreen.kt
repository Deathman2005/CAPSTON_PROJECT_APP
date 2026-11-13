package com.smsshield.app.ui.screens.settings

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
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
import com.smsshield.app.service.SMSNotificationListener
import com.smsshield.app.util.PermissionUtils
import com.smsshield.app.ui.theme.*
import com.smsshield.app.ui.viewmodel.SettingsViewModel

@Composable
fun SettingsScreen(
    viewModel: SettingsViewModel,
    onNavigateBack: () -> Unit
) {
    val preferences by viewModel.userPreferences.collectAsState()
    val context = LocalContext.current
    val scrollState = rememberScrollState()

    var showDeleteDialog by remember { mutableStateOf(false) }
    var showPrivacyDialog by remember { mutableStateOf(false) }
    var backendUrlInput by remember { mutableStateOf(preferences.backendUrl) }

    LaunchedEffect(preferences.backendUrl) {
        backendUrlInput = preferences.backendUrl
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(ShieldDarkBg)
            .padding(horizontal = 16.dp)
            .verticalScroll(scrollState)
    ) {
        Spacer(modifier = Modifier.height(16.dp))

        // Top Header
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(onClick = onNavigateBack) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = Color.White)
            }
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = "Settings & Privacy",
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Monitoring Toggle Section
        Text("NOTIFICATION MONITORING", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = ShieldCyan)
        Spacer(modifier = Modifier.height(8.dp))

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
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Real-Time Notification Guard",
                            fontSize = 14.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = Color.White
                        )
                        Text(
                            text = "Analyze SMS notifications automatically as they arrive from approved apps.",
                            fontSize = 11.sp,
                            color = Color.Gray,
                            modifier = Modifier.padding(top = 2.dp)
                        )
                    }

                    Switch(
                        checked = preferences.isMonitoringEnabled,
                        onCheckedChange = { viewModel.toggleMonitoring(it) },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Color.Black,
                            checkedTrackColor = ShieldCyan,
                            uncheckedThumbColor = Color.Gray,
                            uncheckedTrackColor = ShieldBorder
                        )
                    )
                }

                HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp), color = ShieldBorder)

                var isSystemAccessGranted by remember { mutableStateOf(PermissionUtils.isNotificationListenerEnabled(context)) }
                LifecycleResumeEffect(Unit) {
                    isSystemAccessGranted = PermissionUtils.isNotificationListenerEnabled(context)
                    onPauseOrDispose { }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Android System Access",
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Medium,
                            color = Color.White
                        )
                        Text(
                            text = if (isSystemAccessGranted) "Granted & Active" else "Not granted in Android Settings",
                            fontSize = 11.sp,
                            color = if (isSystemAccessGranted) ShieldSafe else ShieldWarning
                        )
                    }

                    if (!isSystemAccessGranted) {
                        TextButton(
                            onClick = {
                                try {
                                    context.startActivity(PermissionUtils.createNotificationListenerSettingsIntent())
                                } catch (_: Exception) {
                                    Toast.makeText(context, "Could not open Settings", Toast.LENGTH_SHORT).show()
                                }
                            }
                        ) {
                            Text("Grant Access", color = ShieldCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                        }
                    } else {
                        Icon(Icons.Default.CheckCircle, contentDescription = null, tint = ShieldSafe, modifier = Modifier.size(20.dp))
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Device Optimization & Background Reliability (Crucial for Xiaomi / HyperOS / MIUI)
        Text("DEVICE RELIABILITY & AUTO-TRIGGER", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = ShieldCyan)
        Spacer(modifier = Modifier.height(8.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = ShieldCardBg),
            shape = RoundedCornerShape(12.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder)
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.BatteryChargingFull,
                        contentDescription = null,
                        tint = ShieldCyan,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = if (PermissionUtils.isXiaomiDevice()) "Xiaomi / HyperOS / MIUI Guard" else "Background Protection Guard",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = Color.White
                    )
                }

                Text(
                    text = "Aggressive OEM battery managers frequently terminate background notification listeners. To ensure 24/7 real-time fraud detection, verify these two settings:",
                    fontSize = 11.sp,
                    color = Color.LightGray,
                    lineHeight = 16.sp
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("1. Autostart Permission", fontSize = 12.sp, fontWeight = FontWeight.Medium, color = Color.White)
                        Text("Allows SMS Shield to restart after reboot", fontSize = 10.sp, color = Color.Gray)
                    }
                    TextButton(
                        onClick = {
                            val opened = PermissionUtils.openXiaomiAutostart(context)
                            if (!opened) {
                                PermissionUtils.requestIgnoreBatteryOptimizations(context)
                            }
                        }
                    ) {
                        Text("Configure", color = ShieldCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                }

                HorizontalDivider(color = ShieldBorder)

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("2. Battery Saver: No Restrictions", fontSize = 12.sp, fontWeight = FontWeight.Medium, color = Color.White)
                        Text("Prevents OS from killing the real-time guard", fontSize = 10.sp, color = Color.Gray)
                    }
                    TextButton(
                        onClick = {
                            PermissionUtils.requestIgnoreBatteryOptimizations(context)
                        }
                    ) {
                        Text("Exempt", color = ShieldCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Approved SMS Apps Section
        Text("SUPPORTED SMS SOURCES", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = ShieldCyan)
        Spacer(modifier = Modifier.height(8.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = ShieldCardBg),
            shape = RoundedCornerShape(12.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder)
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = "SMS Shield strictly monitors notifications only from these verified packages:",
                    fontSize = 11.sp,
                    color = Color.LightGray
                )

                SMSNotificationListener.SUPPORTED_SMS_PACKAGES.forEach { pkg ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.CheckCircle, contentDescription = null, tint = ShieldSafe, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Column {
                            val name = when {
                                pkg.contains("google") -> "Google Messages"
                                pkg.contains("samsung") -> "Samsung Messages"
                                else -> "Xiaomi / System Messages"
                            }
                            Text(name, fontSize = 13.sp, fontWeight = FontWeight.Medium, color = Color.White)
                            Text(pkg, fontSize = 10.sp, color = Color.Gray)
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Backend URL Configuration
        Text("AI BACKEND CONNECTION", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = ShieldCyan)
        Spacer(modifier = Modifier.height(8.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = ShieldCardBg),
            shape = RoundedCornerShape(12.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder)
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = "Backend Service Endpoint",
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Medium,
                    color = Color.White
                )
                Text(
                    text = "For Android Emulator use http://10.0.2.2:8000. For physical phones use your local LAN IP.",
                    fontSize = 11.sp,
                    color = Color.Gray
                )

                OutlinedTextField(
                    value = backendUrlInput,
                    onValueChange = { backendUrlInput = it },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = ShieldCyan,
                        unfocusedBorderColor = ShieldBorder,
                        focusedContainerColor = ShieldDarkBg,
                        unfocusedContainerColor = ShieldDarkBg,
                        focusedTextColor = Color.White,
                        unfocusedTextColor = Color.White
                    ),
                    singleLine = true
                )

                Button(
                    onClick = {
                        viewModel.updateBackendUrl(backendUrlInput)
                        Toast.makeText(context, "Backend URL updated", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier.align(Alignment.End),
                    colors = ButtonDefaults.buttonColors(containerColor = ShieldCyan),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text("Save URL", color = Color.Black, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Privacy & Data Storage Section
        Text("PRIVACY & RETENTION", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = ShieldCyan)
        Spacer(modifier = Modifier.height(8.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = ShieldCardBg),
            shape = RoundedCornerShape(12.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder)
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Local Data Retention", fontSize = 13.sp, color = Color.White)
                    Text("${preferences.dataRetentionDays} Days", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = ShieldCyan)
                }

                Divider(color = ShieldBorder)

                OutlinedButton(
                    onClick = { showPrivacyDialog = true },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder)
                ) {
                    Icon(Icons.Default.PrivacyTip, contentDescription = null, tint = ShieldCyan, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Read Full Privacy Policy", color = Color.White, fontSize = 12.sp)
                }

                Button(
                    onClick = { showDeleteDialog = true },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = ShieldDanger.copy(alpha = 0.2f)),
                    shape = RoundedCornerShape(8.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, ShieldDanger)
                ) {
                    Icon(Icons.Default.Delete, contentDescription = null, tint = ShieldDanger, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Delete All Scan History", color = ShieldDanger, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // App Version
        Column(
            modifier = Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text("SMS Shield for Android v0.1.0", fontSize = 11.sp, color = Color.Gray)
            Text("Phase 1 Android Application Foundation", fontSize = 10.sp, color = Color.DarkGray)
        }

        Spacer(modifier = Modifier.height(36.dp))
    }

    // Delete Confirmation Dialog
    if (showDeleteDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            title = { Text("Delete All Scan History?", color = Color.White, fontWeight = FontWeight.Bold) },
            text = { Text("This will permanently remove all local scan audit records. Raw messages are never retained.", color = Color.LightGray, fontSize = 13.sp) },
            confirmButton = {
                TextButton(
                    onClick = {
                        viewModel.clearAllHistory {
                            Toast.makeText(context, "Scan history purged", Toast.LENGTH_SHORT).show()
                        }
                        showDeleteDialog = false
                    }
                ) {
                    Text("DELETE ALL", color = ShieldDanger, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteDialog = false }) {
                    Text("Cancel", color = Color.Gray)
                }
            },
            containerColor = ShieldCardBg,
            shape = RoundedCornerShape(12.dp)
        )
    }

    // Privacy Policy Dialog
    if (showPrivacyDialog) {
        AlertDialog(
            onDismissRequest = { showPrivacyDialog = false },
            title = { Text("SMS Shield Privacy Policy", color = Color.White, fontWeight = FontWeight.Bold) },
            text = {
                Column(
                    modifier = Modifier
                        .verticalScroll(rememberScrollState())
                        .padding(vertical = 4.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text("1. Zero Raw SMS Storage: We do not store or transmit raw message content. Only risk classifications and URL reputation metadata are logged.", fontSize = 12.sp, color = Color.LightGray)
                    Text("2. No Inbox Permissions: SMS Shield never requests READ_SMS or RECEIVE_SMS permissions.", fontSize = 12.sp, color = Color.LightGray)
                    Text("3. Opt-in Notification Access: Monitoring is off by default and inspects only supported SMS applications (Google Messages & Samsung Messages).", fontSize = 12.sp, color = Color.LightGray)
                    Text("4. Local Processing: OTPs, PINs, and credentials are scrubbed locally before analysis.", fontSize = 12.sp, color = Color.LightGray)
                }
            },
            confirmButton = {
                TextButton(onClick = { showPrivacyDialog = false }) {
                    Text("Close", color = ShieldCyan, fontWeight = FontWeight.Bold)
                }
            },
            containerColor = ShieldCardBg,
            shape = RoundedCornerShape(12.dp)
        )
    }
}

