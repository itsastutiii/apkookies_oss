package com.apkookies.sdk

import retrofit2.http.Body
import retrofit2.http.POST

interface BankApi {
    @POST("v1/signals/device-health")
    suspend fun postDeviceHealth(@Body signals: DeviceSignals): DeviceHealthResponse
}