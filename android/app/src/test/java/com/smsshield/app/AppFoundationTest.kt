package com.smsshield.app

import com.smsshield.app.service.SMSNotificationListener
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppFoundationTest {

    @Test
    fun testApprovedSmsPackageRegistry() {
        val approved = SMSNotificationListener.SUPPORTED_SMS_PACKAGES

        // Verify approved SMS packages
        assertTrue(approved.contains("com.google.android.apps.messaging"))
        assertTrue(approved.contains("com.samsung.android.messaging"))

        // Strictly verify that unrelated packages are NOT supported
        assertFalse(approved.contains("com.whatsapp"))
        assertFalse(approved.contains("org.telegram.messenger"))
        assertFalse(approved.contains("com.google.android.gm"))
        assertFalse(approved.contains("com.instagram.android"))
    }

    @Test
    fun testInitialServiceStateDisconnected() {
        assertFalse(SMSNotificationListener.isConnected)
    }
}
