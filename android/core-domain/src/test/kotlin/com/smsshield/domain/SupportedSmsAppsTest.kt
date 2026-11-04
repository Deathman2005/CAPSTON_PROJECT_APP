package com.smsshield.domain

import com.smsshield.domain.registry.SupportedSmsApps
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SupportedSmsAppsTest {

    @Test
    fun testApprovedPackagesAreAccepted() {
        assertTrue(SupportedSmsApps.isSupported("com.google.android.apps.messaging"))
        assertTrue(SupportedSmsApps.isSupported("com.samsung.android.messaging"))

        // Case-insensitivity and whitespace handling
        assertTrue(SupportedSmsApps.isSupported("  COM.GOOGLE.ANDROID.APPS.MESSAGING  "))
        assertTrue(SupportedSmsApps.isSupported("com.samsung.android.messaging "))
    }

    @Test
    fun testSocialMessengersAreStrictlyRejected() {
        assertFalse(SupportedSmsApps.isSupported("com.whatsapp"), "WhatsApp must be rejected")
        assertFalse(SupportedSmsApps.isSupported("com.whatsapp.w4b"), "WhatsApp Business must be rejected")
        assertFalse(SupportedSmsApps.isSupported("org.telegram.messenger"), "Telegram must be rejected")
        assertFalse(SupportedSmsApps.isSupported("org.thoughtcrime.securesms"), "Signal must be rejected")
        assertFalse(SupportedSmsApps.isSupported("com.facebook.orca"), "Facebook Messenger must be rejected")
        assertFalse(SupportedSmsApps.isSupported("com.instagram.android"), "Instagram must be rejected")
    }

    @Test
    fun testEmailAndBankingAppsAreStrictlyRejected() {
        assertFalse(SupportedSmsApps.isSupported("com.google.android.gm"), "Gmail must be rejected")
        assertFalse(SupportedSmsApps.isSupported("com.microsoft.office.outlook"), "Outlook must be rejected")
        assertFalse(SupportedSmsApps.isSupported("com.sbi.lotusintouch"), "SBI Yono must be rejected")
        assertFalse(SupportedSmsApps.isSupported("com.snapwork.hdfc"), "HDFC MobileBanking must be rejected")
    }

    @Test
    fun testNullAndBlankPackagesRejected() {
        assertFalse(SupportedSmsApps.isSupported(null))
        assertFalse(SupportedSmsApps.isSupported(""))
        assertFalse(SupportedSmsApps.isSupported("   "))
    }

    @Test
    fun testMetadataRetrieval() {
        val googleInfo = SupportedSmsApps.getAppInfo("com.google.android.apps.messaging")
        assertNotNull(googleInfo)
        assertEquals("Google Messages", googleInfo.displayName)
        assertEquals("Google LLC", googleInfo.vendor)

        val nullInfo = SupportedSmsApps.getAppInfo("com.unsupported.app")
        assertNull(nullInfo)

        val allApps = SupportedSmsApps.getAllSupported()
        assertEquals(2, allApps.size)
    }
}

