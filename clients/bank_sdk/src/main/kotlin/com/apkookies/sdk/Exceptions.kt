package com.apkookies.sdk

sealed class ApkookiesException(message: String, cause: Throwable? = null) : Exception(message, cause)

class NetworkException(message: String, cause: Throwable) : ApkookiesException(message, cause)

class ApiException(val code: Int, override val message: String) : ApkookiesException("API error $code: $message")

class UnexpectedException(message: String, cause: Throwable) : ApkookiesException(message, cause)
