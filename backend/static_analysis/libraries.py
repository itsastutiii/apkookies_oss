"""Third-party library code: which call sites belong to SDKs rather than the app.

Almost every Android app bundles SDKs (AndroidX, Google Play services, OkHttp,
Facebook, Flutter, ...) that themselves call "sensitive" APIs: AndroidX draws
popup windows with WindowManager.addView, accessibility helpers live in
androidx.core, OkHttp opens sockets. Counting those calls as the app's own
behaviour made genuine apps look like trojans (a bank app scored 0.90 from SDK
calls). API-usage detection therefore ignores call sites inside known library
packages.

Approach and its limits. Research tools identify libraries by CODE, not by
package name: LibScout (Backes et al., CCS 2016) matches class-hierarchy
profiles that survive identifier renaming, and LibRadar (Ma et al., ICSE 2016
companion) clusters API-call fingerprints of package subtrees across millions
of apps. We use the simplest version of the same idea: a documented prefix list
of common SDK packages (below). Two consequences:
  * an SDK that is obfuscated/renamed (e.g. into `a.b.c`) isn't recognised, so
    its calls still count as the app's (errs towards flagging);
  * malware can hide code under a library-looking package name (e.g. its own
    `com/google/...` class). That's why the manifest gates in api_usage.py
    (a declared accessibility service, SYSTEM_ALERT_WINDOW) don't depend on this
    list, and why a library match never clears a manifest-declared component.
Replacing the list with code-based detection (LibScout-style profiles) is
planned.

Prefixes are DEX class descriptors ("L" + package path with "/").
"""
from __future__ import annotations

LIBRARY_PREFIXES: tuple[str, ...] = (
    # Android platform support libraries
    "Landroidx/", "Landroid/support/", "Lcom/google/android/material/",
    # Google (Play services, Firebase, Guava, Gson, ML Kit, ...)
    "Lcom/google/",
    # Kotlin and coroutines
    "Lkotlin/", "Lkotlinx/",
    # Networking and serialization
    "Lokhttp3/", "Lokio/", "Lretrofit2/", "Lcom/squareup/", "Lcom/fasterxml/",
    "Lorg/apache/", "Lorg/json/",
    # Cross-platform frameworks
    "Lio/flutter/", "Lcom/facebook/", "Lio/invertase/", "Lexpo/modules/",
    # Rx, DI, images
    "Lio/reactivex/", "Lrx/", "Ldagger/", "Ljavax/inject/", "Lcom/bumptech/glide/",
    "Lcom/airbnb/lottie/",
    # Analytics, crash reporting and engagement SDKs common in Indian finance apps
    "Lio/sentry/", "Lcom/crashlytics/", "Lcom/appsflyer/", "Lcom/adjust/sdk/",
    "Lio/branch/", "Lcom/clevertap/", "Lcom/moengage/", "Lcom/webengage/",
    "Lcom/onesignal/", "Lcom/microsoft/", "Lcom/amazon/",
)


def is_library(location: str) -> bool:
    """`location` is 'Lpkg/Cls;->method' or a class descriptor 'Lpkg/Cls;'."""
    return location.startswith(LIBRARY_PREFIXES)
