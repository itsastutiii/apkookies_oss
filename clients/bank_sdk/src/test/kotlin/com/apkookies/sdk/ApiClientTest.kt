package com.apkookies.sdk

import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class ApiClientTest {
    private lateinit var server: MockWebServer

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun postsBackendCompatibleDeviceHealthPayload() = runBlocking {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("""{"device_risk_score":0.4,"action":"warn","reasons":["Root indicators present"]}"""),
        )

        val response = ApiClient(server.url("/").toString()).postDeviceHealth(
            DeviceSignals(
                packageName = "com.example.bank",
                playIntegrityToken = "token",
                sideloadedApps = listOf("com.example.side"),
                accessibilityServicesEnabled = listOf("com.example.acc"),
                unknownSourcesEnabled = true,
                isRootedHint = true,
                developerMode = true,
                overlayPermissionApps = listOf("com.example.overlay"),
            ),
        )

        val request = server.takeRequest()
        val body = request.body.readUtf8()
        assertEquals("/v1/signals/device-health", request.path)
        assertTrue(body.contains("\"package_name\":\"com.example.bank\""))
        assertTrue(body.contains("\"play_integrity_token\":\"token\""))
        assertTrue(body.contains("\"sideloaded_apps\":[\"com.example.side\"]"))
        assertTrue(body.contains("\"accessibility_services_enabled\":[\"com.example.acc\"]"))
        assertTrue(body.contains("\"unknown_sources_enabled\":true"))
        assertTrue(body.contains("\"is_rooted_hint\":true"))
        assertTrue(body.contains("\"developer_mode\":true"))
        assertTrue(body.contains("\"overlay_permission_apps\":[\"com.example.overlay\"]"))

        assertEquals(0.4, response.deviceRiskScore, 0.0)
        assertEquals("warn", response.action)
        assertEquals(listOf("Root indicators present"), response.reasons)
    }

    @Test
    fun rejectsInvalidBaseUrl() {
        val exception = runCatching { ApiClient("ftp://risk.example.com") }.exceptionOrNull()

        assertTrue(exception is IllegalArgumentException)
        assertEquals("baseUrl must use http or https", exception?.message)
    }

    @Test(expected = ApiException::class)
    fun throwsApiExceptionOnNon2xxResponse() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(400))
        ApiClient(server.url("/").toString()).postDeviceHealth(
            DeviceSignals(packageName = "test")
        )
        Unit
    }
}
