package com.smsshield.domain.parser

import java.util.regex.Pattern

/**
 * Defensive URL extractor for SMS message text.
 * Strictly avoids treating email addresses as URLs and strips trailing punctuation.
 */
object UrlExtractor {

    // RFC-compliant URL pattern supporting http/https and explicit domain patterns
    private val URL_PATTERN = Pattern.compile(
        """(?i)\b(?:https?://|www\.)[a-zA-Z0-9.\-_]+(?::\d+)?(?:/[^\s]*)?"""
    )

    private val EMAIL_PATTERN = Pattern.compile(
        """(?i)^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$"""
    )

    /**
     * Extracts all unique normalized URLs from the provided text.
     */
    fun extractUrls(text: String?): List<String> {
        if (text.isNullOrBlank()) return emptyList()

        val results = mutableListOf<String>()
        val matcher = URL_PATTERN.matcher(text)

        while (matcher.find()) {
            var candidate = matcher.group()

            // Trim common trailing punctuation often caught at sentence boundaries
            candidate = candidate.trimEnd('.', ',', ';', '!', '?', ')', ']', '}', '>', '"', '\'')

            // Ensure it is not an email address
            if (!EMAIL_PATTERN.matcher(candidate).matches()) {
                val normalized = if (!candidate.startsWith("http://", ignoreCase = true) &&
                    !candidate.startsWith("https://", ignoreCase = true)
                ) {
                    "http://$candidate"
                } else {
                    candidate
                }
                if (!results.contains(normalized)) {
                    results.add(normalized)
                }
            }
        }

        return results
    }
}
