package com.smsshield.app.ui.screens.scanner

import android.Manifest
import android.content.pm.PackageManager
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.smsshield.app.ui.scanner.PortraitCaptureActivity
import com.smsshield.app.ui.theme.*
import com.smsshield.app.ui.viewmodel.ScanMode
import com.smsshield.app.ui.viewmodel.ScanUiState
import com.smsshield.app.ui.viewmodel.ScannerViewModel
import com.smsshield.domain.model.ScanItem
import com.smsshield.domain.model.SecurityClassification

@Composable
fun ScannerScreen(
    viewModel: ScannerViewModel,
    initialSharedText: String? = null,
    onNavigateBack: () -> Unit
) {
    val scanMode by viewModel.scanMode.collectAsState()
    val messageText by viewModel.messageText.collectAsState()
    val qrText by viewModel.qrText.collectAsState()
    val extractedUrls by viewModel.extractedUrls.collectAsState()
    val scanState by viewModel.scanState.collectAsState()
    val clipboardManager = LocalClipboardManager.current
    val scrollState = rememberScrollState()
    val context = LocalContext.current

    // Activity Result Launcher for ZXing Fullscreen Camera Barcode Scanner
    val qrLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val scanned = result.contents
        if (!scanned.isNullOrBlank()) {
            viewModel.updateQrText(scanned)
            viewModel.scanQr(scanned)
            Toast.makeText(context, "QR Code scanned successfully!", Toast.LENGTH_SHORT).show()
        }
    }

    // Helper to build optimized portrait QR scan options
    val createScanOptions = {
        ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt("")
            setCameraId(0) // Back camera
            setBeepEnabled(true)
            setBarcodeImageEnabled(false)
            setOrientationLocked(true) // Strictly lock to portrait
            setCaptureActivity(PortraitCaptureActivity::class.java)
        }
    }

    // Camera Permission Launcher
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted) {
            qrLauncher.launch(createScanOptions())
        } else {
            Toast.makeText(context, "Camera permission is required to scan QR codes", Toast.LENGTH_LONG).show()
        }
    }

    val startCameraScanner = {
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            qrLauncher.launch(createScanOptions())
        } else {
            permissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    // Pre-populate message text if launched via Sharesheet
    LaunchedEffect(initialSharedText) {
        if (!initialSharedText.isNullOrBlank()) {
            if (initialSharedText.startsWith("upi://", ignoreCase = true)) {
                viewModel.setScanMode(ScanMode.QR)
                viewModel.updateQrText(initialSharedText)
            } else {
                viewModel.setScanMode(ScanMode.SMS)
                viewModel.updateMessageText(initialSharedText)
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(ShieldDarkBg)
            .padding(horizontal = 16.dp)
            .verticalScroll(scrollState),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(16.dp))

        // Top Navigation Bar
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(onClick = onNavigateBack) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = Color.White)
            }
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = "Explainable Threat Scanner",
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Mode Switcher Tabs [SMS / Messages | UPI / QR Code]
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(ShieldCardBg, RoundedCornerShape(10.dp))
                .padding(4.dp),
            horizontalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Surface(
                modifier = Modifier
                    .weight(1f)
                    .clickable { viewModel.setScanMode(ScanMode.SMS) },
                shape = RoundedCornerShape(8.dp),
                color = if (scanMode == ScanMode.SMS) ShieldCyan else Color.Transparent
            ) {
                Row(
                    modifier = Modifier.padding(vertical = 8.dp),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Default.Message,
                        contentDescription = null,
                        tint = if (scanMode == ScanMode.SMS) Color.Black else Color.Gray,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "SMS Message",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (scanMode == ScanMode.SMS) Color.Black else Color.Gray
                    )
                }
            }

            Surface(
                modifier = Modifier
                    .weight(1f)
                    .clickable { viewModel.setScanMode(ScanMode.QR) },
                shape = RoundedCornerShape(8.dp),
                color = if (scanMode == ScanMode.QR) ShieldCyan else Color.Transparent
            ) {
                Row(
                    modifier = Modifier.padding(vertical = 8.dp),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Default.QrCodeScanner,
                        contentDescription = null,
                        tint = if (scanMode == ScanMode.QR) Color.Black else Color.Gray,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "UPI / QR Code",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (scanMode == ScanMode.QR) Color.Black else Color.Gray
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(14.dp))

        // Content Area Based on Mode
        if (scanMode == ScanMode.SMS) {
            // SMS Message Input Box
            OutlinedTextField(
                value = messageText,
                onValueChange = { viewModel.updateMessageText(it) },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(140.dp),
                label = { Text("Enter or Paste SMS Text") },
                placeholder = { Text("e.g. Your electricity will be disconnected tonight. Pay immediately at http://...") },
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = ShieldCyan,
                    unfocusedBorderColor = ShieldBorder,
                    focusedContainerColor = ShieldCardBg,
                    unfocusedContainerColor = ShieldCardBg,
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White,
                    focusedLabelColor = ShieldCyan,
                    unfocusedLabelColor = Color.Gray
                ),
                trailingIcon = {
                    if (messageText.isNotEmpty()) {
                        IconButton(onClick = { viewModel.clear() }) {
                            Icon(Icons.Default.Close, contentDescription = "Clear", tint = Color.Gray)
                        }
                    }
                }
            )

            Spacer(modifier = Modifier.height(6.dp))

            // Action Toolbar (Paste & Clear)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextButton(
                    onClick = {
                        val clip = clipboardManager.getText()
                        if (clip != null) {
                            viewModel.updateMessageText(clip.text)
                        }
                    }
                ) {
                    Icon(Icons.Default.ContentPaste, contentDescription = null, tint = ShieldCyan, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Paste from Clipboard", color = ShieldCyan, fontSize = 12.sp)
                }

                if (extractedUrls.isNotEmpty()) {
                    Surface(
                        color = ShieldCyanDark.copy(alpha = 0.5f),
                        shape = RoundedCornerShape(4.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, ShieldCyan)
                    ) {
                        Text(
                            text = "${extractedUrls.size} URL(s) detected",
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                            fontSize = 11.sp,
                            color = ShieldCyan
                        )
                    }
                }
            }

            // Extracted URLs Chips
            if (extractedUrls.isNotEmpty()) {
                Spacer(modifier = Modifier.height(4.dp))
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = ShieldCardBg),
                    shape = RoundedCornerShape(8.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder)
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Text("Extracted URLs to Verify:", fontSize = 11.sp, color = Color.Gray)
                        extractedUrls.forEach { url ->
                            Text(
                                text = url,
                                fontSize = 12.sp,
                                color = ShieldCyan,
                                maxLines = 1,
                                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Scan Action Button
            Button(
                onClick = { viewModel.scanMessage(if (initialSharedText != null) "manual_share" else "manual_input") },
                enabled = messageText.isNotBlank() && scanState !is ScanUiState.Loading,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = ShieldCyan,
                    disabledContainerColor = ShieldCyan.copy(alpha = 0.2f)
                ),
                shape = RoundedCornerShape(10.dp)
            ) {
                if (scanState is ScanUiState.Loading) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), color = Color.Black, strokeWidth = 2.dp)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Analyzing Threat Signatures...", color = Color.Black, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                } else {
                    Icon(Icons.Default.Shield, contentDescription = null, tint = Color.Black, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Analyze Message", color = Color.Black, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                }
            }
        } else {
            // Live Camera Scan Hero Card
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { startCameraScanner() },
                colors = CardDefaults.cardColors(containerColor = ShieldCyan.copy(alpha = 0.12f)),
                shape = RoundedCornerShape(12.dp),
                border = androidx.compose.foundation.BorderStroke(1.5.dp, ShieldCyan)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Surface(
                        color = ShieldCyan,
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.size(46.dp)
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Icon(
                                Icons.Default.QrCodeScanner,
                                contentDescription = "Camera QR Scanner",
                                tint = Color.Black,
                                modifier = Modifier.size(26.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.width(12.dp))

                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Scan QR Code with Camera",
                            color = Color.White,
                            fontWeight = FontWeight.Bold,
                            fontSize = 15.sp
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = "Point camera at any UPI / Payment QR code to inspect for fraud in real-time.",
                            color = Color.LightGray,
                            fontSize = 11.sp,
                            lineHeight = 15.sp
                        )
                    }

                    Icon(
                        Icons.Default.ChevronRight,
                        contentDescription = null,
                        tint = ShieldCyan,
                        modifier = Modifier.size(22.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Or Manual Input Divider
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Divider(modifier = Modifier.weight(1f), color = ShieldBorder)
                Text(
                    text = "  OR PASTE UPI INTENT  ",
                    color = Color.Gray,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.SemiBold
                )
                Divider(modifier = Modifier.weight(1f), color = ShieldBorder)
            }

            Spacer(modifier = Modifier.height(14.dp))

            // UPI / QR Code Input Box
            OutlinedTextField(
                value = qrText,
                onValueChange = { viewModel.updateQrText(it) },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(120.dp),
                label = { Text("Enter or Paste UPI Intent / QR Link") },
                placeholder = { Text("e.g. upi://pay?pa=cashback@upi&pn=Reward&am=2000&tn=Scan+to+receive+cashback") },
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = ShieldCyan,
                    unfocusedBorderColor = ShieldBorder,
                    focusedContainerColor = ShieldCardBg,
                    unfocusedContainerColor = ShieldCardBg,
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White,
                    focusedLabelColor = ShieldCyan,
                    unfocusedLabelColor = Color.Gray
                ),
                trailingIcon = {
                    if (qrText.isNotEmpty()) {
                        IconButton(onClick = { viewModel.clear() }) {
                            Icon(Icons.Default.Close, contentDescription = "Clear", tint = Color.Gray)
                        }
                    }
                }
            )

            Spacer(modifier = Modifier.height(6.dp))

            // Quick Actions (Paste from Clipboard & Info)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextButton(
                    onClick = {
                        val clip = clipboardManager.getText()
                        if (clip != null) {
                            viewModel.updateQrText(clip.text)
                        }
                    }
                ) {
                    Icon(Icons.Default.ContentPaste, contentDescription = null, tint = ShieldCyan, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Paste from Clipboard", color = ShieldCyan, fontSize = 12.sp)
                }

                Surface(
                    color = ShieldWarning.copy(alpha = 0.15f),
                    shape = RoundedCornerShape(4.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, ShieldWarning.copy(alpha = 0.5f))
                ) {
                    Text(
                        text = "UPI Safety Shield",
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                        fontSize = 10.sp,
                        color = ShieldWarning
                    )
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Scan QR Action Button
            Button(
                onClick = { viewModel.scanQr(qrText) },
                enabled = qrText.isNotBlank() && scanState !is ScanUiState.Loading,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = ShieldCyan,
                    disabledContainerColor = ShieldCyan.copy(alpha = 0.2f)
                ),
                shape = RoundedCornerShape(10.dp)
            ) {
                if (scanState is ScanUiState.Loading) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), color = Color.Black, strokeWidth = 2.dp)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Deconstructing UPI Intent...", color = Color.Black, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                } else {
                    Icon(Icons.Default.QrCodeScanner, contentDescription = null, tint = Color.Black, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Analyze UPI / QR Intent", color = Color.Black, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Scan Results / Error View
        when (val state = scanState) {
            is ScanUiState.Error -> {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = ShieldDanger.copy(alpha = 0.12f)),
                    shape = RoundedCornerShape(10.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, ShieldDanger)
                ) {
                    Row(modifier = Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Error, contentDescription = null, tint = ShieldDanger)
                        Spacer(modifier = Modifier.width(10.dp))
                        Text(text = state.message, fontSize = 13.sp, color = Color.White)
                    }
                }
            }

            is ScanUiState.Success -> {
                ScanResultCard(
                    scanItem = state.result,
                    onInspectUrl = { url -> viewModel.scanUrl(url) }
                )
            }

            else -> {}
        }

        Spacer(modifier = Modifier.height(32.dp))
    }
}

@Composable
fun ScanResultCard(
    scanItem: ScanItem,
    onInspectUrl: ((String) -> Unit)? = null
) {
    val (statusColor, statusBg) = when (scanItem.classification) {
        SecurityClassification.SAFE -> ShieldSafe to ShieldSafe.copy(alpha = 0.15f)
        SecurityClassification.SUSPICIOUS -> ShieldWarning to ShieldWarning.copy(alpha = 0.15f)
        SecurityClassification.MALICIOUS -> ShieldDanger to ShieldDanger.copy(alpha = 0.15f)
        SecurityClassification.UNKNOWN -> ShieldUnknown to ShieldUnknown.copy(alpha = 0.15f)
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = ShieldCardBg),
        shape = RoundedCornerShape(12.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, statusColor)
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            // Status Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Surface(
                    color = statusBg,
                    shape = RoundedCornerShape(6.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, statusColor)
                ) {
                    Text(
                        text = scanItem.classification.name,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = statusColor
                    )
                }

                if (scanItem.riskScore != null) {
                    Column(horizontalAlignment = Alignment.End) {
                        Text("Risk Score", fontSize = 10.sp, color = Color.Gray)
                        Text(
                            text = "${scanItem.riskScore} / 100",
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Bold,
                            color = statusColor
                        )
                    }
                }
            }

            // Specialized UPI Intent Card (if QR / UPI intent scanned)
            val upiDetails = scanItem.upiDetails
            if (upiDetails != null) {
                UpiPaymentIntentCard(
                    upi = upiDetails,
                    classification = scanItem.classification
                )
            }

            // Rich Explainable AI Card (Groq AI explanation, bilingual Hindi toggle, token attribution highlighting)
            val explanation = scanItem.explanation
            if (explanation != null) {
                ExplainableAiCard(
                    explanation = explanation,
                    scannedText = scanItem.scannedText
                )
            } else {
                // Fallback Classic Section
                Divider(color = ShieldBorder)

                Column {
                    Text("Recommended Action", fontSize = 11.sp, color = Color.Gray)
                    Text(
                        text = scanItem.recommendation,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = Color.White
                    )
                }

                if (scanItem.detectionReasons.isNotEmpty()) {
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("Triggered Security Indicators", fontSize = 11.sp, color = Color.Gray)
                        scanItem.detectionReasons.forEach { reason ->
                            Row(verticalAlignment = Alignment.Top) {
                                Text("•", color = statusColor, fontSize = 14.sp)
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(reason, fontSize = 12.sp, color = Color.LightGray)
                            }
                        }
                    }
                }
            }

            // Extracted Link Details (if URLs detected)
            if (scanItem.extractedUrls.isNotEmpty()) {
                Divider(color = ShieldBorder)
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Identified Links (${scanItem.urlCount})", fontSize = 11.sp, color = Color.Gray)
                    scanItem.extractedUrls.forEach { url ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = url,
                                fontSize = 12.sp,
                                color = ShieldCyan,
                                maxLines = 1,
                                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                                modifier = Modifier.weight(1f)
                            )
                            if (onInspectUrl != null) {
                                Spacer(modifier = Modifier.width(8.dp))
                                OutlinedButton(
                                    onClick = { onInspectUrl(url) },
                                    modifier = Modifier.height(28.dp),
                                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp),
                                    border = androidx.compose.foundation.BorderStroke(1.dp, ShieldCyan)
                                ) {
                                    Text("Inspect", fontSize = 10.sp, color = ShieldCyan)
                                }
                            }
                        }
                    }
                }
            }

            Divider(color = ShieldBorder)

            // Audit & Provenance Footer
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text("Source: ${scanItem.sourceCategory}", fontSize = 10.sp, color = Color.Gray)
                if (scanItem.payloadType != null) {
                    Text("Type: ${scanItem.payloadType}", fontSize = 10.sp, color = Color.Gray)
                }
                Text("Scan ID: ${scanItem.id.take(8)}...", fontSize = 10.sp, color = Color.Gray)
            }
        }
    }
}
