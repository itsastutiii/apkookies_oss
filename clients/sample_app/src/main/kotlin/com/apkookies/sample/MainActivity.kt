package com.apkookies.sample

import android.os.Bundle
import android.widget.CheckBox
import android.widget.EditText
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.apkookies.sdk.ApkookiesSdk
import com.apkookies.sdk.DeviceSignals
import com.apkookies.sdk.DeviceHealthAction
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {
    private lateinit var sdk: ApkookiesSdk

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val statusText = findViewById<TextView>(R.id.statusText)
        val customerIdInput = findViewById<EditText>(R.id.customerIdInput)
        val passwordInput = findViewById<EditText>(R.id.passwordInput)
        val demoModeCheck = findViewById<CheckBox>(R.id.demoModeCheck)
        val loginButton = findViewById<Button>(R.id.loginButton)

        sdk = ApkookiesSdk(
            context = applicationContext,
            baseUrl = "http://10.0.2.2:8000/",
            cloudProjectNumber = 535608211910L,
        )

        loginButton.setOnClickListener {
            if (customerIdInput.text.isNullOrBlank() || passwordInput.text.isNullOrBlank()) {
                statusText.text = "Enter your Customer ID and password"
                return@setOnClickListener
            }

            loginButton.isEnabled = false
            statusText.text = "Verifying device security..."
            lifecycleScope.launch {
                try {
                    val action = if (demoModeCheck.isChecked) {
                        sdk.checkDeviceHealth(demoSignals())
                    } else {
                        sdk.checkDeviceHealth(packageName)
                    }
                    showSecurityResult(action)
                } catch (e: Exception) {
                    statusText.text = "Error: ${e.message}"
                } finally {
                    loginButton.isEnabled = true
                }
            }
        }
    }

    private fun demoSignals() = DeviceSignals(
        packageName = "com.example.bank",
        playIntegrityToken = null,
        sideloadedApps = listOf("test.app.one", "test.app.two", "test.app.three"),
        accessibilityServicesEnabled = listOf("test.accessibility"),
        unknownSourcesEnabled = true,
        isRootedHint = true,
        developerMode = true,
        overlayPermissionApps = listOf("overlay.app"),
    )

    private fun showSecurityResult(action: DeviceHealthAction) {
        val safe = action is DeviceHealthAction.Allow
        val title = if (safe) "Device safe" else "Device unsafe"
        val message = when (action) {
            DeviceHealthAction.Allow -> "Security verification passed."
            is DeviceHealthAction.Warn -> "Warning detected:\n${action.reasons.joinToString("\n")}" 
            is DeviceHealthAction.Block -> "Login blocked by device security:\n${action.reasons.joinToString("\n")}"
        }
        statusTextForResult(title)
        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton("OK", null)
            .show()
    }

    private fun statusTextForResult(title: String) {
        findViewById<TextView>(R.id.statusText).text = title
    }
}
