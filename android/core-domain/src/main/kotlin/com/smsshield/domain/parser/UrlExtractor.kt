package com.smsshield.domain.parser

import java.net.URI
import java.net.IDN
import java.util.Locale
import java.util.regex.Pattern

/**
 * Detailed metadata of an analyzed URL.
 */
data class ExtractedUrl(
    val original: String,
    val normalized: String,
    val hostname: String,
    val isIpAddress: Boolean,
    val isShortened: Boolean,
    val isPunycode: Boolean,
    val hasDeceptiveSubdomains: Boolean
)

/**
 * Advanced, defensive URL extractor for SMS message text.
 *
 * Implements strict RFC normalization, trailing punctuation stripping,
 * IP-address detection, shortener detection, Punycode detection, and
 * email address exclusion.
 */
object UrlExtractor {

    // Known URL shortener domains commonly abused in SMS phishing
    val KNOWN_SHORTENERS = setOf(
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
        "cutt.ly", "rb.gy", "goo.gl", "bit.do", "shorte.st", "adf.ly"
    )

    // Suspicious TLDs frequently encountered in spam/phishing campaigns
    val SUSPICIOUS_TLDS = setOf(
        "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "loan", "club",
        "click", "link", "guru", "buzz", "live"
    )

    // Targets http, https, www., and common hostname/path patterns
    private val URL_REGEX = Pattern.compile(
        """(?i)\b(?:(?:https?://|www\.)[a-zA-Z0-9.\-_]+(?::\d+)?(?:/[^\s]*)?|(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?)"""
    )

    // Standard email pattern to ensure email addresses are not treated as URLs
    private val EMAIL_REGEX = Pattern.compile(
        """(?i)^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$"""
    )

    // IPv4 Address Pattern
    private val IPV4_REGEX = Pattern.compile(
        """^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d+)?$"""
    )

    /**
     * Extracts and normalizes all unique URLs from raw message text.
     */
    fun extractUrls(text: String?): List<String> {
        return analyzeUrls(text).map { it.normalized }
    }

    /**
     * Extracts full ExtractedUrl metadata objects for security feature inspection.
     */
    fun analyzeUrls(text: String?): List<ExtractedUrl> {
        if (text.isNullOrBlank()) return emptyList()

        val results = mutableListOf<ExtractedUrl>()
        val seenNormalized = mutableSetOf<String>()
        val matcher = URL_REGEX.matcher(text)

        while (matcher.find()) {
            val startIndex = matcher.start()
            // Strictly skip domain names that are part of an email address (preceded by '@')
            if (startIndex > 0 && text[startIndex - 1] == '@') continue

            val rawCandidate = matcher.group()
            val cleanCandidate = stripSurroundingPunctuation(rawCandidate)

            if (cleanCandidate.isBlank()) continue

            // Strictly skip email addresses or mailto links
            if (cleanCandidate.contains("@") || cleanCandidate.startsWith("mailto:", ignoreCase = true) || EMAIL_REGEX.matcher(cleanCandidate).matches()) continue

            val normalizedUrl = normalizeUrl(cleanCandidate) ?: continue
            val host = extractHostname(normalizedUrl) ?: continue

            // Prevent duplicate entries
            if (!seenNormalized.add(normalizedUrl.lowercase(Locale.ROOT))) continue

            val isIp = isIpAddress(host)
            val isShort = isShortenedUrl(host)
            val isPuny = host.startsWith("xn--", ignoreCase = true) || host.contains(".xn--", ignoreCase = true)
            val deceptive = hasDeceptiveSubdomains(host)

            results.add(
                ExtractedUrl(
                    original = cleanCandidate,
                    normalized = normalizedUrl,
                    hostname = host,
                    isIpAddress = isIp,
                    isShortened = isShort,
                    isPunycode = isPuny,
                    hasDeceptiveSubdomains = deceptive
                )
            )
        }

        return results
    }

    /**
     * Strips leading and trailing punctuation characters commonly found in natural language text.
     */
    fun stripSurroundingPunctuation(input: String): String {
        var str = input.trim()

        // Strip leading punctuation like '(' or '<' or '"'
        while (str.isNotEmpty() && (str.startsWith("(") || str.startsWith("[") || str.startsWith("<") || str.startsWith("\"") || str.startsWith("'"))) {
            str = str.substring(1).trim()
        }

        // Strip trailing punctuation like '.', ',', ';', '!', '?', ')', ']', '>', '"', '\''
        val trailingChars = charArrayOf('.', ',', ';', '!', '?', ')', ']', '}', '>', '"', '\'', ':')
        while (str.isNotEmpty() && trailingChars.contains(str.last())) {
            str = str.substring(0, str.length - 1).trim()
        }

        return str
    }

    /**
     * Normalizes a URL string: ensures http/https scheme, lowercases host, formats punycode if needed.
     */
    fun normalizeUrl(candidate: String): String? {
        val withScheme = if (!candidate.startsWith("http://", ignoreCase = true) &&
            !candidate.startsWith("https://", ignoreCase = true)
        ) {
            "http://$candidate"
        } else {
            candidate
        }

        return try {
            val uri = URI(withScheme)
            val rawHost = uri.host ?: return null
            if (!rawHost.contains(".")) return null

            // Handle Internationalized Domain Names (IDN) safely
            val asciiHost = try {
                IDN.toASCII(rawHost)
            } catch (e: Exception) {
                rawHost.lowercase(Locale.ROOT)
            }

            val scheme = uri.scheme?.lowercase(Locale.ROOT) ?: "http"
            val portPart = if (uri.port != -1 && uri.port != 80 && uri.port != 443) ":${uri.port}" else ""
            val rawPath = uri.rawPath ?: ""
            val rawQuery = if (uri.rawQuery != null) "?${uri.rawQuery}" else ""

            "$scheme://${asciiHost.lowercase(Locale.ROOT)}$portPart$rawPath$rawQuery"
        } catch (e: Exception) {
            // If URI parsing fails, return a safe fallback if valid structure
            if (withScheme.contains("://") && withScheme.length > 8) withScheme else null
        }
    }

    /**
     * Extracts the hostname component from a URL.
     */
    fun extractHostname(url: String): String? {
        return try {
            val uri = URI(url)
            uri.host?.lowercase(Locale.ROOT)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Checks if a host is an IPv4 address.
     */
    fun isIpAddress(hostname: String): Boolean {
        return IPV4_REGEX.matcher(hostname).matches()
    }

    /**
     * Checks if a domain belongs to a known URL shortener service.
     */
    fun isShortenedUrl(hostname: String): Boolean {
        val lower = hostname.lowercase(Locale.ROOT)
        return KNOWN_SHORTENERS.any { lower == it || lower.endsWith(".$it") }
    }

    /**
     * Identifies deceptive subdomain structures often seen in phishing,
     * such as sbi.com.update-kyc.xyz or bank.com-login.top.
     */
    fun hasDeceptiveSubdomains(hostname: String): Boolean {
        val parts = hostname.split(".")
        if (parts.size >= 4) return true

        val sensitiveKeywords = listOf("bank", "sbi", "hdfc", "icici", "kyc", "otp", "login", "verify", "secure", "update")
        val tld = parts.lastOrNull() ?: ""

        // If a high-risk TLD contains trusted banking keywords in subdomains
        if (SUSPICIOUS_TLDS.contains(tld)) {
            val subdomainPart = parts.dropLast(2).joinToString(".")
            if (sensitiveKeywords.any { subdomainPart.contains(it) }) {
                return true
            }
        }

        return false
    }
}
