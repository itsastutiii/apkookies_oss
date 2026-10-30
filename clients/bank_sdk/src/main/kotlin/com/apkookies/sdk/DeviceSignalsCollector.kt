package com.apkookies.sdk

import android.app.AppOpsManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.provider.Settings
import android.util.Base64
import android.util.Log
import kotlinx.coroutines.tasks.await
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.security.SecureRandom

/**
 * Raw device-health signals. Mirrors backend DeviceSignals (POST /v1/signals/device-health).
 * Keep field names in sync with the backend Pydantic model.
 */
@Serializable
data class DeviceSignals(
    @SerialName("package_name")
    val packageName: String,
    @SerialName("play_integrity_token")
    val playIntegrityToken: String? = null,
    @SerialName("sideloaded_apps")
    val sideloadedApps: List<String> = emptyList(),
    @SerialName("accessibility_services_enabled")
    val accessibilityServicesEnabled: List<String> = emptyList(),
    @SerialName("unknown_sources_enabled")
    val unknownSourcesEnabled: Boolean = false,
    @SerialName("is_rooted_hint")
    val isRootedHint: Boolean = false,
    @SerialName("developer_mode")
    val developerMode: Boolean = false,
    @SerialName("overlay_permission_apps")
    val overlayPermissionApps: List<String> = emptyList(),
)

@Serializable
data class DeviceHealthResponse(
    @SerialName("device_risk_score")
    val deviceRiskScore: Double,
    val action: String,
    val reasons: List<String>,
)

interface PlayIntegrityTokenProvider {
    suspend fun requestToken(packageName: String): String?
}

class AndroidPlayIntegrityTokenProvider(
    context: Context,
    private val cloudProjectNumber: Long? = null,
) : PlayIntegrityTokenProvider {
    private val appContext = context.applicationContext
    private val integrityManager by lazy {
        com.google.android.play.core.integrity.IntegrityManagerFactory.create(appContext)
    }
    private val secureRandom = SecureRandom()

    override suspend fun requestToken(packageName: String): String? {
        if (cloudProjectNumber == null) {
            Log.i("ApkookiesSdk", "Skipping Play Integrity token request: cloudProjectNumber is null (required for library usage).")
            return null
        }
        return try {
            val nonceBytes = ByteArray(32).also(secureRandom::nextBytes)
            val nonce = Base64.encodeToString(nonceBytes, Base64.NO_WRAP or Base64.URL_SAFE)
            val requestBuilder = com.google.android.play.core.integrity.IntegrityTokenRequest.builder()
                .setNonce(nonce)
                .setCloudProjectNumber(cloudProjectNumber)

            val task = integrityManager.requestIntegrityToken(requestBuilder.build())
            task.await().token()
        } catch (e: Throwable) {
            Log.e("ApkookiesSdk", "Play Integrity token request failed for $packageName", e)
            null
        }
    }
}

/** Collects passive, best-effort signals from Android framework services. */
class DeviceSignalsCollector(
    private val context: Context,
    private val playIntegrityTokenProvider: PlayIntegrityTokenProvider? =
        AndroidPlayIntegrityTokenProvider(context),
) {
    suspend fun collect(packageName: String): DeviceSignals {
        return DeviceSignals(
            packageName = packageName,
            playIntegrityToken = playIntegrityTokenProvider?.requestToken(packageName),
            sideloadedApps = sideloadedApps(),
            accessibilityServicesEnabled = enabledAccessibilityServices(),
            unknownSourcesEnabled = unknownSourcesEnabled(),
            isRootedHint = rootIndicatorsPresent(),
            developerMode = developerModeEnabled(),
            overlayPermissionApps = overlayPermissionApps(),
        )
    }

    private fun sideloadedApps(): List<String> {
        val packageManager = context.packageManager
        val approvedInstallers = setOf("com.android.vending", "com.google.android.packageinstaller")
        return packageManager.getInstalledApplications(0).asSequence()
            .filter { it.packageName != context.packageName }
            .filter { application ->
                val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    runCatching {
                        packageManager.getInstallSourceInfo(application.packageName).installingPackageName
                    }.getOrNull()
                } else {
                    @Suppress("DEPRECATION")
                    packageManager.getInstallerPackageName(application.packageName)
                }
                installer.isNullOrEmpty() || installer !in approvedInstallers
            }
            .map(ApplicationInfo::packageName)
            .toList()
    }

    private fun enabledAccessibilityServices(): List<String> {
        val raw = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
        ) ?: return emptyList()
        return parseAccessibilityServices(raw)
    }

    private fun unknownSourcesEnabled(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.packageManager.canRequestPackageInstalls()
        } else {
            Settings.Secure.getInt(
                context.contentResolver,
                "install_non_market_apps",
                0,
            ) != 0
        }
    }

    private fun overlayPermissionApps(): List<String> {
        val appOps = context.getSystemService(AppOpsManager::class.java) ?: return emptyList()
        return context.packageManager.getInstalledApplications(0).asSequence()
            .filter { application ->
                runCatching {
                    // unsafeCheckOpNoThrow exists only on API 29+, but minSdk is 24. Without
                    // the fallback the call throws on Android 7-9, runCatching turns that
                    // into "false", and overlay-capable apps silently go unreported.
                    val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        appOps.unsafeCheckOpNoThrow(
                            AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW,
                            application.uid,
                            application.packageName,
                        )
                    } else {
                        @Suppress("DEPRECATION")
                        appOps.checkOpNoThrow(
                            AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW,
                            application.uid,
                            application.packageName,
                        )
                    }
                    mode == AppOpsManager.MODE_ALLOWED
                }.getOrDefault(false)
            }
            .map(ApplicationInfo::packageName)
            .toList()
    }

    private fun developerModeEnabled(): Boolean {
        return Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
            0,
        ) != 0
    }

    private fun rootIndicatorsPresent(): Boolean {
        val testKeys = Build.TAGS?.contains("test-keys") == true
        val knownPaths = arrayOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
            "/data/adb/magisk", "/data/adb/zygisk",
        )
        return testKeys || knownPaths.any { java.io.File(it).exists() }
    }

    companion object {
        internal fun parseAccessibilityServices(raw: String): List<String> =
            raw.split(':')
                .mapNotNull { runCatching { ComponentName.unflattenFromString(it)?.packageName }.getOrNull() }
                .distinct()
    }
}
