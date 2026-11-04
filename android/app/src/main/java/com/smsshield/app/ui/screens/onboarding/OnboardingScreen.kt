package com.smsshield.app.ui.screens.onboarding

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.smsshield.app.ui.theme.*
import com.smsshield.app.ui.viewmodel.OnboardingViewModel

@Composable
fun OnboardingScreen(
    viewModel: OnboardingViewModel,
    onNavigateNext: () -> Unit
) {
    val optInChecked by viewModel.optInChecked.collectAsState()
    val scrollState = rememberScrollState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(ShieldDarkBg)
            .padding(horizontal = 20.dp)
            .verticalScroll(scrollState),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(36.dp))

        // Shield Logo & Brand
        Surface(
            shape = RoundedCornerShape(16.dp),
            color = ShieldCyan.copy(alpha = 0.12f),
            border = androidx.compose.foundation.BorderStroke(1.dp, ShieldCyan.copy(alpha = 0.3f)),
            modifier = Modifier.size(72.dp)
        ) {
            Box(contentAlignment = Alignment.Center) {
                Icon(
                    imageVector = Icons.Default.Shield,
                    contentDescription = null,
                    tint = ShieldCyan,
                    modifier = Modifier.size(40.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Welcome to SMS Shield",
            style = MaterialTheme.typography.titleLarge,
            color = Color.White,
            fontWeight = FontWeight.Bold
        )

        Text(
            text = "AI-Powered Real-Time Scam & Phishing Detection",
            fontSize = 13.sp,
            color = Color.LightGray,
            modifier = Modifier.padding(top = 4.dp)
        )

        Spacer(modifier = Modifier.height(24.dp))

        // What we process card
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = ShieldCardBg),
            shape = RoundedCornerShape(12.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder)
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Security, contentDescription = null, tint = ShieldSafe, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("What SMS Shield Analyzes", fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = Color.White)
                }
                FeaturePoint("Supported SMS notifications when opt-in monitoring is enabled")
                FeaturePoint("Web links and URLs extracted to check against threat databases")
                FeaturePoint("Manual pasted or shared messages you submit for scanning")
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // What we NEVER collect card
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = ShieldCardBg),
            shape = RoundedCornerShape(12.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, ShieldBorder)
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Close, contentDescription = null, tint = ShieldDanger, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Strict Privacy Protections", fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = Color.White)
                }
                NegativePoint("NO full SMS inbox access (no READ_SMS permission)")
                NegativePoint("NO raw message storage on disk or servers")
                NegativePoint("NO OTP, PIN, password, or bank card collection")
                NegativePoint("NO access to contacts or personal media")
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        // Opt-in Checkbox Card
        Surface(
            color = ShieldCyanDark.copy(alpha = 0.35f),
            shape = RoundedCornerShape(12.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, ShieldCyan.copy(alpha = 0.5f)),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Checkbox(
                    checked = optInChecked,
                    onCheckedChange = { viewModel.setOptIn(it) },
                    colors = CheckboxDefaults.colors(
                        checkedColor = ShieldCyan,
                        uncheckedColor = Color.Gray,
                        checkmarkColor = Color.Black
                    )
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "I understand SMS Shield inspects notifications from approved SMS apps only, and I agree to the Privacy Policy.",
                    fontSize = 12.sp,
                    color = Color.White,
                    lineHeight = 16.sp
                )
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // Continue Button
        Button(
            onClick = {
                viewModel.completeOnboarding {
                    onNavigateNext()
                }
            },
            enabled = optInChecked,
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = ShieldCyan,
                disabledContainerColor = ShieldCyan.copy(alpha = 0.2f)
            ),
            shape = RoundedCornerShape(10.dp)
        ) {
            Text(
                text = "Continue to Permission Setup",
                color = if (optInChecked) Color.Black else Color.Gray,
                fontWeight = FontWeight.Bold,
                fontSize = 14.sp
            )
        }

        Spacer(modifier = Modifier.height(36.dp))
    }
}

@Composable
private fun FeaturePoint(text: String) {
    Row(verticalAlignment = Alignment.Top) {
        Icon(Icons.Default.Check, contentDescription = null, tint = ShieldSafe, modifier = Modifier.size(16.dp))
        Spacer(modifier = Modifier.width(8.dp))
        Text(text = text, fontSize = 12.sp, color = Color.LightGray)
    }
}

@Composable
private fun NegativePoint(text: String) {
    Row(verticalAlignment = Alignment.Top) {
        Icon(Icons.Default.Close, contentDescription = null, tint = ShieldDanger, modifier = Modifier.size(16.dp))
        Spacer(modifier = Modifier.width(8.dp))
        Text(text = text, fontSize = 12.sp, color = Color.LightGray)
    }
}

