package com.smsshield.app.ui.screens.scanner

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.smsshield.app.ui.theme.*
import com.smsshield.domain.model.ExplanationApiModel
import com.smsshield.domain.model.SecurityClassification
import com.smsshield.domain.model.TokenSpanApiModel
import com.smsshield.domain.model.UpiIntentApiModel

/**
 * Builds an AnnotatedString that highlights suspicious risk words in red and safe words in green.
 */
fun buildHighlightedAnnotatedString(
    text: String,
    attributions: List<TokenSpanApiModel>
): AnnotatedString {
    if (attributions.isEmpty()) {
        return AnnotatedString(text)
    }

    val validSpans = attributions.filter { it.start in 0..text.length && it.end in 0..text.length && it.start < it.end }
        .sortedBy { it.start }

    return buildAnnotatedString {
        var currentIndex = 0
        for (span in validSpans) {
            if (span.start > currentIndex) {
                append(text.substring(currentIndex, span.start))
            }
            if (span.start >= currentIndex) {
                val spanText = text.substring(span.start, span.end)
                val (bg, fg) = when (span.impact.lowercase()) {
                    "risk" -> Color(0x45EF4444) to Color(0xFFFCA5A5)
                    "safe" -> Color(0x3510B981) to Color(0xFF6EE7B7)
                    else -> Color(0x206B7280) to Color.White
                }
                val startPos = length
                append(spanText)
                addStyle(
                    style = SpanStyle(
                        background = bg,
                        color = fg,
                        fontWeight = FontWeight.Bold
                    ),
                    start = startPos,
                    end = length
                )
                currentIndex = span.end
            }
        }
        if (currentIndex < text.length) {
            append(text.substring(currentIndex))
        }
    }
}

/**
 * Visual card showing the scanned SMS with inline token attribution highlighting.
 */
@Composable
fun HighlightedMessagePreview(
    scannedText: String,
    attributions: List<TokenSpanApiModel>,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = ShieldDarkBg),
        shape = RoundedCornerShape(10.dp),
        border = BorderStroke(1.dp, ShieldBorder)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Highlight,
                        contentDescription = null,
                        tint = ShieldCyan,
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "Visual Token Attribution (XAI)",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = ShieldCyan
                    )
                }

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(modifier = Modifier.size(8.dp).background(ShieldDanger, CircleShape))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Risk Word", fontSize = 9.sp, color = Color.Gray)
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(modifier = Modifier.size(8.dp).background(ShieldSafe, CircleShape))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Safe", fontSize = 9.sp, color = Color.Gray)
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            val annotatedText = remember(scannedText, attributions) {
                buildHighlightedAnnotatedString(scannedText, attributions)
            }

            Text(
                text = annotatedText,
                fontSize = 13.sp,
                lineHeight = 18.sp,
                color = Color.White
            )
        }
    }
}

/**
 * Complete Explainable AI card providing headline verdict, why flagged description,
 * actionable safety steps, and Hindi language translation toggle.
 */
@Composable
fun ExplainableAiCard(
    explanation: ExplanationApiModel,
    scannedText: String?,
    modifier: Modifier = Modifier
) {
    var isHindiSelected by remember { mutableStateOf(false) }
    val hindi = explanation.hindi

    val currentTitle = if (isHindiSelected && hindi != null) {
        hindi.summary_title
    } else {
        explanation.summary_title
    }

    val currentWhyFlagged = if (isHindiSelected && hindi != null) {
        hindi.why_flagged
    } else {
        explanation.why_flagged
    }

    val currentActions = if (isHindiSelected && hindi != null && hindi.recommended_actions.isNotEmpty()) {
        hindi.recommended_actions
    } else {
        explanation.recommended_actions
    }

    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = ShieldCardBg),
        shape = RoundedCornerShape(12.dp),
        border = BorderStroke(1.dp, ShieldCyan.copy(alpha = 0.6f))
    ) {
        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            // Top Bar: AI Badge + Language Switcher
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Surface(
                    color = ShieldCyanDark.copy(alpha = 0.5f),
                    shape = RoundedCornerShape(6.dp),
                    border = BorderStroke(1.dp, ShieldCyan)
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.AutoAwesome,
                            contentDescription = null,
                            tint = ShieldCyan,
                            modifier = Modifier.size(13.dp)
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = if (explanation.is_ai_generated) "Groq AI Explanation" else "Verified XAI Reasoning",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = ShieldCyan
                        )
                    }
                }

                // Bilingual Toggle Switch [EN | हिंदी]
                if (explanation.hindi != null) {
                    Surface(
                        color = ShieldDarkBg,
                        shape = RoundedCornerShape(16.dp),
                        border = BorderStroke(1.dp, ShieldBorder)
                    ) {
                        Row(modifier = Modifier.padding(2.dp)) {
                            Box(
                                modifier = Modifier
                                    .background(
                                        if (!isHindiSelected) ShieldCyan else Color.Transparent,
                                        RoundedCornerShape(14.dp)
                                    )
                                    .clickable { isHindiSelected = false }
                                    .padding(horizontal = 10.dp, vertical = 3.dp)
                            ) {
                                Text(
                                    text = "EN",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = if (!isHindiSelected) Color.Black else Color.Gray
                                )
                            }
                            Box(
                                modifier = Modifier
                                    .background(
                                        if (isHindiSelected) ShieldCyan else Color.Transparent,
                                        RoundedCornerShape(14.dp)
                                    )
                                    .clickable { isHindiSelected = true }
                                    .padding(horizontal = 10.dp, vertical = 3.dp)
                            ) {
                                Text(
                                    text = "हिंदी",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = if (isHindiSelected) Color.Black else Color.Gray
                                )
                            }
                        }
                    }
                }
            }

            // Headline Title
            Text(
                text = currentTitle,
                fontSize = 16.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )

            // Why Flagged Section
            Surface(
                color = ShieldDarkBg.copy(alpha = 0.7f),
                shape = RoundedCornerShape(8.dp),
                border = BorderStroke(1.dp, ShieldBorder)
            ) {
                Column(modifier = Modifier.padding(10.dp)) {
                    Text(
                        text = if (isHindiSelected) "यह संदेश क्यों संदिग्ध है?" else "Why was this flagged?",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = ShieldCyan
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = currentWhyFlagged,
                        fontSize = 12.sp,
                        lineHeight = 17.sp,
                        color = Color(0xFFE5E7EB)
                    )
                }
            }

            // Inline Highlighted Preview (if token attributions exist)
            if (!scannedText.isNullOrBlank() && explanation.token_attributions.isNotEmpty()) {
                HighlightedMessagePreview(
                    scannedText = scannedText,
                    attributions = explanation.token_attributions
                )
            }

            // Top Risk Tokens Chips
            if (explanation.top_risk_tokens.isNotEmpty()) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        text = if (isHindiSelected) "पहचाने गए संदिग्ध शब्द" else "Identified Suspicious Keywords",
                        fontSize = 11.sp,
                        color = Color.Gray
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        explanation.top_risk_tokens.take(4).forEach { token ->
                            Surface(
                                color = ShieldDanger.copy(alpha = 0.15f),
                                shape = RoundedCornerShape(6.dp),
                                border = BorderStroke(1.dp, ShieldDanger.copy(alpha = 0.5f))
                            ) {
                                Text(
                                    text = "⚠ $token",
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    color = ShieldDanger
                                )
                            }
                        }
                    }
                }
            }

            // Actionable Steps Protocol
            if (currentActions.isNotEmpty()) {
                Surface(
                    color = Color(0x1510B981),
                    shape = RoundedCornerShape(8.dp),
                    border = BorderStroke(1.dp, ShieldSafe.copy(alpha = 0.4f))
                ) {
                    Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.CheckCircle,
                                contentDescription = null,
                                tint = ShieldSafe,
                                modifier = Modifier.size(14.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = if (isHindiSelected) "सुरक्षा निर्देश (क्या करें / क्या न करें)" else "Recommended Action Checklist",
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                color = ShieldSafe
                            )
                        }
                        currentActions.forEachIndexed { idx, action ->
                            Row(verticalAlignment = Alignment.Top) {
                                Text(
                                    text = "${idx + 1}.",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = ShieldSafe
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    text = action,
                                    fontSize = 12.sp,
                                    color = Color.White,
                                    lineHeight = 16.sp
                                )
                            }
                        }
                    }
                }
            }

            // Model Provenance Footer
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Model: ${explanation.model_used}",
                    fontSize = 10.sp,
                    color = Color.Gray
                )
                Text(
                    text = "Category: ${explanation.fraud_type}",
                    fontSize = 10.sp,
                    color = Color.Gray
                )
            }
        }
    }
}

/**
 * Specialized card displaying decoded UPI payment intent details and anti-fraud warnings.
 */
@Composable
fun UpiPaymentIntentCard(
    upi: UpiIntentApiModel,
    classification: SecurityClassification,
    modifier: Modifier = Modifier
) {
    val isDanger = classification == SecurityClassification.MALICIOUS

    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = ShieldCardBg),
        shape = RoundedCornerShape(12.dp),
        border = BorderStroke(1.dp, if (isDanger) ShieldDanger else ShieldSafe)
    ) {
        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            // Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.QrCodeScanner,
                        contentDescription = null,
                        tint = if (isDanger) ShieldDanger else ShieldCyan,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "UPI Payment Intent Details",
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )
                }

                Surface(
                    color = if (isDanger) ShieldDanger.copy(alpha = 0.2f) else ShieldSafe.copy(alpha = 0.2f),
                    shape = RoundedCornerShape(4.dp),
                    border = BorderStroke(1.dp, if (isDanger) ShieldDanger else ShieldSafe)
                ) {
                    Text(
                        text = if (isDanger) "HIGH-RISK INTENT" else "STANDARD INTENT",
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (isDanger) ShieldDanger else ShieldSafe
                    )
                }
            }

            // CRITICAL UPI RULE BANNER
            Surface(
                color = ShieldDanger.copy(alpha = 0.15f),
                shape = RoundedCornerShape(8.dp),
                border = BorderStroke(1.dp, ShieldDanger)
            ) {
                Row(modifier = Modifier.padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Warning, contentDescription = null, tint = ShieldDanger, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "UPI Security Rule: Scanning a QR code DEBITS money. You NEVER need to enter a UPI PIN to receive money.",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = Color.White
                    )
                }
            }

            // UPI Parameter Rows
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(ShieldDarkBg, RoundedCornerShape(8.dp))
                    .padding(10.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                val pn = upi.pn
                if (!pn.isNullOrBlank()) {
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Payee Name (pn):", fontSize = 11.sp, color = Color.Gray)
                        Text(pn, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color.White)
                    }
                }

                val pa = upi.pa
                if (!pa.isNullOrBlank()) {
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Payee VPA (pa):", fontSize = 11.sp, color = Color.Gray)
                        Text(pa, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = ShieldCyan)
                    }
                }

                val am = upi.am
                if (am != null) {
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Requested Amount:", fontSize = 11.sp, color = Color.Gray)
                        Text("₹$am", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = ShieldDanger)
                    }
                }

                val tn = upi.tn
                if (!tn.isNullOrBlank()) {
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Transaction Note (tn):", fontSize = 11.sp, color = Color.Gray)
                        Text(tn, fontSize = 12.sp, color = Color.White)
                    }
                }

                val mc = upi.mc
                if (!mc.isNullOrBlank()) {
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Merchant Code (mc):", fontSize = 11.sp, color = Color.Gray)
                        Text(mc, fontSize = 11.sp, color = Color.LightGray)
                    }
                }
            }
        }
    }
}

