# Bank App SDK (Android / Kotlin)

> **Status: coming soon (prototype).** What exists today: the SDK collects device-health signals and gets allow/warn/block from `POST /v1/signals/device-health`, scored server-side with hand-set weights; Play Integrity tokens are passed through but **not verified server-side**; unit-tested against a mock server only, not integrated into a bank app.

Passive device-health signal collector. On login it gathers signals and sends the
**raw** data to the backend, which computes the composite score. The SDK only
**blocks/warns** based on the returned `action` — no scoring logic ships in the app.

## Contract
`POST {baseUrl}/v1/signals/device-health` → `{ device_risk_score, action, reasons }`

## Usage

Create the SDK with an application `Context` and the backend base URL.

```kotlin
val sdk = ApkookiesSdk(
	context = applicationContext,
	baseUrl = "https://risk.example.com/",
)

when (val action = sdk.checkDeviceHealth(packageName)) {
	DeviceHealthAction.Allow -> continueLogin()
	is DeviceHealthAction.Warn -> showDeviceWarning(action.reasons)
	is DeviceHealthAction.Block -> stopLogin(action.reasons)
}
```

The SDK posts raw signals to `POST /v1/signals/device-health`; risk scoring and
the final action remain server-side.

## Publishing

The release artifact is `com.apkookies:bank-sdk:1.0.0`. Build and publish it to
a configured Maven repository with `./gradlew :clients:bank_sdk:publish`.

## Collected signals

The collector uses `PackageManager`, `Settings.Secure`, `Settings.Global`, and
`AppOpsManager` to collect sideloaded applications, enabled accessibility
services, unknown-source installation state, overlay-capable applications, root
indicators, and developer mode. Android package visibility restrictions and OEM
behavior can make these lists best-effort.

Play Integrity is requested by the default provider. Its token is optional: if
Play services are unavailable, the request fails, or the app is distributed
outside Google Play, collection continues with a null token. Supply a custom
`PlayIntegrityTokenProvider` to use another attestation flow or deterministic
test token.

## Testing

`ApiClientTest` uses MockWebServer to verify the exact endpoint path, snake_case
JSON payload, and response deserialization. Framework-backed collectors should
be exercised with Android instrumented tests on the target API level. A live
backend test should be enabled only in an environment that provides its base URL.
