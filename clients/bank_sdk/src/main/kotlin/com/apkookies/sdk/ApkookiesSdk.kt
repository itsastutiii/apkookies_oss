package com.apkookies.sdk

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * APKookies bank-app SDK (Android library).
 *
 * Passively collects device-health signals on login and sends the RAW signals to
 * the backend, which computes the composite score server-side. The SDK only
 * blocks/warns based on the returned action — no scoring logic ships in the app,
 * so policy/model updates never require an app release.
 */
class ApkookiesSdk(
    context: Context,
    private val baseUrl: String,
    /** Google Cloud Project Number (found in Project info in Cloud Console) */
    private val cloudProjectNumber: Long? = null,
    private val apiClient: ApiClient = ApiClient(baseUrl),
    playIntegrityTokenProvider: PlayIntegrityTokenProvider? =
        AndroidPlayIntegrityTokenProvider(context.applicationContext, cloudProjectNumber),
) {
    private val signalCollector = DeviceSignalsCollector(context.applicationContext, playIntegrityTokenProvider)

    /**
     * Call on login. Returns the server-decided action; the app enforces it.
     */
    suspend fun checkDeviceHealth(packageName: String): DeviceHealthAction =
        withContext(Dispatchers.IO) {
            val signals = signalCollector.collect(packageName)
            checkDeviceHealth(signals)
        }

    /** Sends supplied signals to the server, primarily for deterministic demos and tests. */
    suspend fun checkDeviceHealth(signals: DeviceSignals): DeviceHealthAction =
        withContext(Dispatchers.IO) {
            val response = apiClient.postDeviceHealth(signals)
            when (response.action) {
                "block" -> DeviceHealthAction.Block(response.reasons)
                "warn" -> DeviceHealthAction.Warn(response.reasons)
                else -> DeviceHealthAction.Allow
            }
        }
}

sealed class DeviceHealthAction {
    object Allow : DeviceHealthAction()
    data class Warn(val reasons: List<String>) : DeviceHealthAction()
    data class Block(val reasons: List<String>) : DeviceHealthAction()
}
