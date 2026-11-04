package com.smsshield.app.ui.screens.home

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.LifecycleResumeEffect
import com.smsshield.app.ui.theme.*
import com.smsshield.app.ui.viewmodel.HomeViewModel
import com.smsshield.app.util.PermissionUtils
import com.smsshield.domain.model.ScanItem
import com.smsshield.domain.model.SecurityClassification
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun HomeScreen(
    viewModel: HomeViewModel,
    onNavigateToScanner: () -> Unit,
    onNavigateToSettings: () -> Unit
) {
    val uiState by viewModel.uiState.collectAsState()
    val context = LocalContext.current

    LifecycleResumeEffect(Unit) {
        viewModel.updatePermissionStatus(PermissionUtils.isNotificationListenerEnabled(context))
        onPauseOrDispose { }
    }

    Scaffold(
        containerColor = ShieldDarkBg,
        floatingActionButton = {
            FloatingActionButton(
                onClick = onNavigateToScanner,
                containerColor = ShieldCyan,
                contentColor = Color.Black,
                shape = RoundedCornerShape(16.dp)
            ) {
                Icon(Icons.Default.Add, contentDescription = "Scan New SMS")
            }
        }
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                Spacer(modifier = Modifier.height(16.dp))

                // Top Bar
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = "SMS SHIELD",
                                fontSize = 20.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color.White
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Surface(
                                color = ShieldCyan.copy(alpha = 0.15f),
                                shape = RoundedCornerShape(4.dp),
                                border = androidx.compose.foundation.BorderStroke(1.dp, ShieldCyan)
                            ) {
                                Text(
                                    text = "ACTIVE",
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = ShieldCyan
                                )
                            }
                        }
                        Text(
                            text = "Security & Threat Monitor",
                            fontSize = 12.sp,
                            color = Color.Gray
                        )
                    }

                    IconButton(
                        onClick = onNavigateToSettings,
                        modifier = Modifier
                            .background(ShieldCardBg, RoundedCornerShape(10.dp))
                            .border(1.dp, ShieldBorder, RoundedCornerShape(10.dp))
                    ) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings", tint = Color.LightGray)
                    }
                }
            }

            // Real-Time Monitoring Status Banner
            item {
                val isFullyProtected = uiState.isMonitoringEnabled && uiState.isListenerPermissionGranted
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = if (isFullyProtected) ShieldSafe.copy(alpha = 0.12f) else ShieldWarning.copy(alpha = 0.12f)
                    ),
                    shape = RoundedCornerShape(12.dp),
                    border = androidx.compose.foundation.BorderStroke(
                        1.dp,
                        if (isFullyProtected) ShieldSafe.copy(alpha = 0.5f) else ShieldWarning.copy(alpha = 0.5f)
                    )
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                            Icon(
                                imageVector = if (isFullyProtected) Icons.Default.Shield else Icons.Default.Warning,
                                contentDescription = null,
                                tint = if (isFullyProtected) ShieldSafe else ShieldWarning,
                                modifier = Modifier.size(24.dp)
                            )
                            Spacer(modifier = Modifier.width(12.dp))
                            Column {
                                Text(
                                    text = if (isFullyProtected) "Real-Time Guard Active" else "Monitoring Disabled / Paused",
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 13.sp,
                                    color = Color.White
                                )
                                Text(
                                    text = if (isFullyProtected) "Auto-inspecting supported SMS notifications" else "Enable in Settings for real-time alerts",
                                    fontSize = 11.sp,
                                    color = Color.LightGray
                                )
                            }
                        }

                        if (!isFullyProtected) {
                            TextButton(onClick = onNavigateToSettings) {
                                Text("SETUP", color = ShieldCyan, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }

            // Stats Metrics Grid
            item {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        StatTile(
                            modifier = Modifier.weight(1f),
                            title = "Total Scans",
                            value = uiState.totalScans.toString(),
                            icon = Icons.Default.Search,
                            color = ShieldCyan
                        )
                        StatTile(
                            modifier = Modifier.weight(1f),
                            title = "Safe Messages",
                            value = uiState.safeCount.toString(),
                            icon = Icons.Default.CheckCircle,
                            color = ShieldSafe
                        )
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        StatTile(
                            modifier = Modifier.weight(1f),
                            title = "Suspicious",
                            value = uiState.suspiciousCount.toString(),
                            icon = Icons.Default.Warning,
                            color = ShieldWarning
                        )
                        StatTile(
                            modifier = Modifier.weight(1f),
                            title = "Malicious Links",
                            value = uiState.maliciousCount.toString(),
                            icon = Icons.Default.Dangerous,
                            color = ShieldDanger
                        )
                    }
                }
            }

            // Recent Scan History Section Header
            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Recent Scan Activity",
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )
                    Text(
                        text = "${uiState.recentScans.size} entries",
                        fontSize = 12.sp,
                        color = Color.Gray
                    )
                }
            }

            // Recent Scans List or Empty State
            if (uiState.recentScans.isEmpty()) {
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = ShieldCardBg),
                        shape = RoundedCornerShape(12.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder)
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(32.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.Inbox,
                                contentDescription = null,
                                tint = Color.Gray,
                                modifier = Modifier.size(40.dp)
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = "No scan records yet",
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Medium,
                                color = Color.White
                            )
                            Text(
                                text = "Paste a message or use the Android share sheet to analyze suspicious SMS links.",
                                fontSize = 12.sp,
                                color = Color.Gray,
                                textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                                modifier = Modifier.padding(top = 4.dp)
                            )
                        }
                    }
                }
            } else {
                items(uiState.recentScans, key = { it.id }) { scan ->
                    RecentScanCard(scan = scan)
                }
            }

            item {
                Spacer(modifier = Modifier.height(72.dp))
            }
        }
    }
}

@Composable
private fun StatTile(
    modifier: Modifier = Modifier,
    title: String,
    value: String,
    icon: ImageVector,
    color: Color
) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = ShieldCardBg),
        shape = RoundedCornerShape(12.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(text = title, fontSize = 12.sp, color = Color.Gray)
                Icon(imageVector = icon, contentDescription = null, tint = color, modifier = Modifier.size(16.dp))
            }
            Spacer(modifier = Modifier.height(6.dp))
            Text(text = value, fontSize = 22.sp, fontWeight = FontWeight.Bold, color = Color.White)
        }
    }
}

@Composable
private fun RecentScanCard(scan: ScanItem) {
    val (statusColor, statusBg) = when (scan.classification) {
        SecurityClassification.SAFE -> ShieldSafe to ShieldSafe.copy(alpha = 0.15f)
        SecurityClassification.SUSPICIOUS -> ShieldWarning to ShieldWarning.copy(alpha = 0.15f)
        SecurityClassification.MALICIOUS -> ShieldDanger to ShieldDanger.copy(alpha = 0.15f)
        SecurityClassification.UNKNOWN -> ShieldUnknown to ShieldUnknown.copy(alpha = 0.15f)
    }

    val dateFormatter = remember { SimpleDateFormat("MMM dd, HH:mm", Locale.getDefault()) }
    val formattedDate = remember(scan.timestamp) { dateFormatter.format(Date(scan.timestamp)) }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = ShieldCardBg),
        shape = RoundedCornerShape(10.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Surface(
                    color = statusBg,
                    shape = RoundedCornerShape(4.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, statusColor)
                ) {
                    Text(
                        text = scan.classification.name,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = statusColor
                    )
                }

                Text(
                    text = formattedDate,
                    fontSize = 11.sp,
                    color = Color.Gray
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            if (scan.detectionReasons.isNotEmpty()) {
                Text(
                    text = scan.detectionReasons.first(),
                    fontSize = 12.sp,
                    color = Color.White,
                    fontWeight = FontWeight.Medium
                )
            } else {
                Text(
                    text = scan.recommendation,
                    fontSize = 12.sp,
                    color = Color.LightGray
                )
            }

            if (scan.extractedUrls.isNotEmpty()) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Link: ${scan.extractedUrls.first()}",
                    fontSize = 11.sp,
                    color = ShieldCyan,
                    maxLines = 1,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                )
            }
        }
    }
}
