package com.apkookies.sdk

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DeviceSignalsCollectorTest {

    @Test
    fun collectsSignalsWithoutCrashing() = runBlocking {
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        val collector = DeviceSignalsCollector(appContext, playIntegrityTokenProvider = null)
        val signals = collector.collect(appContext.packageName)

        assertNotNull(signals)
        assertEquals(appContext.packageName, signals.packageName)
        
        // Basic sanity checks
        assertNotNull(signals.sideloadedApps)
        assertNotNull(signals.accessibilityServicesEnabled)
        assertNotNull(signals.overlayPermissionApps)
    }

    @Test
    fun parsesAccessibilityComponentPackages() {
        assertEquals(
            listOf("com.example.accessibility"),
            DeviceSignalsCollector.parseAccessibilityServices(
                "com.example.accessibility/com.example.accessibility.AccessibilityService:invalid:com.example.accessibility/com.example.accessibility.AccessibilityService",
            ),
        )
    }
}
