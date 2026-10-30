package com.apkookies.sdk

import kotlinx.serialization.json.Json
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.MediaType.Companion.toMediaType
import retrofit2.Retrofit
import com.jakewharton.retrofit2.converter.kotlinx.serialization.asConverterFactory
import java.net.URI
import java.util.concurrent.TimeUnit

class ApiClient(
    baseUrl: String,
    authTokenProvider: (() -> String?)? = null,
    interceptors: List<Interceptor> = emptyList(),
) {
    private val api: BankApi

    init {
        val httpClient = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .apply {
                authTokenProvider?.let { provider ->
                    addInterceptor { chain ->
                        val request = chain.request().newBuilder().apply {
                            provider()?.takeIf(String::isNotBlank)?.let {
                                addHeader("Authorization", "Bearer $it")
                            }
                        }.build()
                        chain.proceed(request)
                    }
                }
                interceptors.forEach(::addInterceptor)
            }
            .build()
        val json = Json { ignoreUnknownKeys = true }
        api = Retrofit.Builder()
            .baseUrl(normalizeBaseUrl(baseUrl))
            .client(httpClient)
            .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
            .build()
            .create(BankApi::class.java)
    }

    suspend fun postDeviceHealth(signals: DeviceSignals): DeviceHealthResponse =
        try {
            api.postDeviceHealth(signals)
        } catch (e: retrofit2.HttpException) {
            throw ApiException(e.code(), e.message() ?: "Unknown error")
        } catch (e: java.io.IOException) {
            throw NetworkException("Network failure", e)
        } catch (e: Exception) {
            if (e is ApkookiesException) throw e
            throw UnexpectedException("Unexpected error", e)
        }

    private fun normalizeBaseUrl(baseUrl: String): String =
        baseUrl.trim().also { url ->
            require(url.isNotEmpty()) { "baseUrl must not be blank" }
            val scheme = runCatching { URI(url).scheme }.getOrNull()
            require(scheme == "http" || scheme == "https") {
                "baseUrl must use http or https"
            }
        }.let { url -> if (url.endsWith('/')) url else "$url/" }
}
