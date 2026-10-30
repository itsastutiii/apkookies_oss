package com.apkookies.sdk

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

class LiveDeviceHealthIntegrationTest {
    @Test
    fun postsToConfiguredDeviceHealthEndpoint() = runBlocking {
        val baseUrl = System.getenv("BANK_SDK_BASE_URL")
        assumeTrue("BANK_SDK_BASE_URL is not configured", !baseUrl.isNullOrBlank())

        val packageName = System.getenv("BANK_SDK_PACKAGE_NAME") ?: "com.example.bank"
        val response = ApiClient(baseUrl!!).postDeviceHealth(DeviceSignals(packageName))

        assertTrue(response.deviceRiskScore in 0.0..1.0)
        assertTrue(response.action in setOf("allow", "warn", "block"))
    }
}