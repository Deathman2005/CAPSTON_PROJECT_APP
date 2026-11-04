package com.smsshield.domain.registry

/**
 * Metadata descriptor for an approved SMS application.
 */
data class SmsAppInfo(
    val packageName: String,
    val displayName: String,
    val vendor: String,
    val isDefaultSupported: Boolean = true
)

/**
 * Extensible registry of approved SMS messaging applications.
 *
 * NON-NEGOTIABLE SAFETY CONSTRAINT:
 * Only notifications originating from verified SMS applications in this registry
 * will ever be parsed. Notifications from third-party social messengers (WhatsApp,
 * Telegram, Signal), email clients (Gmail, Outlook), or banking apps are strictly
 * rejected at the listener boundary.
 */
object SupportedSmsApps {

    const val PACKAGE_GOOGLE_MESSAGES = "com.google.android.apps.messaging"
    const val PACKAGE_SAMSUNG_MESSAGES = "com.samsung.android.messaging"

    private val APPROVED_APPS = listOf(
        SmsAppInfo(
            packageName = PACKAGE_GOOGLE_MESSAGES,
            displayName = "Google Messages",
            vendor = "Google LLC"
        ),
        SmsAppInfo(
            packageName = PACKAGE_SAMSUNG_MESSAGES,
            displayName = "Samsung Messages",
            vendor = "Samsung Electronics"
        )
    )

    private val APPROVED_PACKAGE_SET = APPROVED_APPS.map { it.packageName }.toSet()

    /**
     * Checks whether the specified package name belongs to a verified, supported SMS application.
     */
    fun isSupported(packageName: String?): Boolean {
        if (packageName.isNullOrBlank()) return false
        return APPROVED_PACKAGE_SET.contains(packageName.trim().lowercase())
    }

    /**
     * Retrieves application metadata for a supported package, or null if unsupported.
     */
    fun getAppInfo(packageName: String?): SmsAppInfo? {
        if (packageName.isNullOrBlank()) return null
        return APPROVED_APPS.firstOrNull { it.packageName.equals(packageName.trim(), ignoreCase = true) }
    }

    /**
     * Returns an unmodifiable list of all currently supported SMS applications.
     */
    fun getAllSupported(): List<SmsAppInfo> = APPROVED_APPS
}

