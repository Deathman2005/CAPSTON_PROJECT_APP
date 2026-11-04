package com.smsshield.app

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.smsshield.app.ui.theme.SMSShieldTheme
import com.smsshield.app.ui.theme.ShieldBorder
import com.smsshield.app.ui.theme.ShieldCardBg
import com.smsshield.app.ui.theme.ShieldCyan

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val sharedText = handleIncomingShareIntent(intent)

        setContent {
            SMSShieldTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    FoundationScreen(initialSharedText = sharedText)
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
    }

    private fun handleIncomingShareIntent(intent: Intent?): String? {
        if (intent?.action == Intent.ACTION_SEND && intent.type == "text/plain") {
            return intent.getStringExtra(Intent.EXTRA_TEXT)
        }
        return null
    }
}

@Composable
fun FoundationScreen(initialSharedText: String?) {
    var messageText by remember { mutableStateOf(initialSharedText ?: "") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Spacer(modifier = Modifier.height(24.dp))

        // Header Title
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "SMS SHIELD",
                fontWeight = FontWeight.Bold,
                fontSize = 24.sp,
                color = Color.White
            )
            Surface(
                color = MaterialTheme.colorScheme.primary.copy(alpha = 0.15f),
                shape = RoundedCornerShape(4.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, ShieldCyan)
            ) {
                Text(
                    text = "PHASE 0",
                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = ShieldCyan
                )
            }
        }

        Text(
            text = "AI-Powered SMS Scam and Malicious URL Detection",
            fontSize = 13.sp,
            color = Color.Gray
        )

        Spacer(modifier = Modifier.height(12.dp))

        // Status Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = ShieldCardBg),
            shape = RoundedCornerShape(12.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = "System Foundation Status",
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 15.sp,
                    color = Color.White
                )
                Spacer(modifier = Modifier.height(8.dp))
                StatusRow(label = "Monitoring", value = "Disabled (Opt-in)")
                StatusRow(label = "Notification Listener", value = "Declared & Isolated")
                StatusRow(label = "SMS Inbox Permissions", value = "None (Privacy First)")
            }
        }

        // Manual Input Area
        OutlinedTextField(
            value = messageText,
            onValueChange = { messageText = it },
            modifier = Modifier
                .fillMaxWidth()
                .height(140.dp),
            label = { Text("Paste or Share Suspicious SMS") },
            placeholder = { Text("e.g., Your bank account is blocked. Update KYC at http://...") },
            shape = RoundedCornerShape(12.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = ShieldCyan,
                unfocusedBorderColor = ShieldBorder,
                focusedContainerColor = ShieldCardBg,
                unfocusedContainerColor = ShieldCardBg,
                focusedTextColor = Color.White,
                unfocusedTextColor = Color.White
            )
        )

        Button(
            onClick = { /* Will trigger backend scan in Phase 1 & 6 */ },
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(10.dp),
            colors = ButtonDefaults.buttonColors(containerColor = ShieldCyan)
        ) {
            Text(text = "Scan Message (Manual Mode)", color = Color.Black, fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
fun StatusRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(text = label, fontSize = 13.sp, color = Color.LightGray)
        Text(text = value, fontSize = 13.sp, fontWeight = FontWeight.Medium, color = ShieldCyan)
    }
}
