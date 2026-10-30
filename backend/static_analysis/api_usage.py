"""Context-aware API-usage analysis, from bytecode cross-references.

We report an API only when app code actually CALLS it (androguard xrefs), with
the calling methods as evidence, instead of when its name appears anywhere in
the DEX string pool. That old text matching flagged log messages and library
names (e.g. `okhttp3` is in nearly every app).

Each rule groups closely related APIs and yields at most ONE observation, so the
per-category counts stay in the small ranges the scoring model expects.
Whether a category is *suspicious* depends on the app's category (a messaging
app reading SMS is normal; a wallpaper app doing it is not).

Only the APP'S OWN code counts: call sites inside known third-party library
packages (AndroidX, Play services, OkHttp, ...) are ignored and counted
(libraries.py explains the approach and its limits). Two capabilities also need
the manifest to back them, because their APIs are used for ordinary UI work:
  * accessibility counts only if the manifest declares a service protected by
    BIND_ACCESSIBILITY_SERVICE, or the app's own class extends AccessibilityService;
  * overlay counts only with the SYSTEM_ALERT_WINDOW permission AND an overlay call
    from the app's own code (WindowManager.addView alone also shows popups/toasts).
If the manifest can't be read, the gates can't be checked and the observations
are kept (fail closed: malware breaks manifests to evade analysers).

Not implemented: data-flow (taint) between these calls, e.g. "SMS body ->
network" (Quark-Engine's step 5; see scoring/rules_engine.py on evidence stages).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from backend.static_analysis.dex_analysis import DexIndex
from backend.static_analysis.libraries import is_library

BIND_ACCESSIBILITY_SERVICE = "android.permission.BIND_ACCESSIBILITY_SERVICE"
SYSTEM_ALERT_WINDOW = "android.permission.SYSTEM_ALERT_WINDOW"


class ApiCategory(str, Enum):
    sms = "sms"
    accessibility = "accessibility"
    overlay = "overlay"
    network = "network"
    telephony = "telephony"
    webview = "webview"
    crypto = "crypto"


@dataclass(frozen=True)
class ApiRule:
    rule_id: str
    category: ApiCategory
    description: str
    calls: tuple[tuple[str, str], ...] = ()   # (class descriptor, method-name regex)
    strings: tuple[str, ...] = ()             # exact strings loaded by code
    subclass_of: tuple[str, ...] = ()         # app classes extending a framework class


_SMS_MGR = "Landroid/telephony/SmsManager;"
_SMS_MSG = "Landroid/telephony/SmsMessage;"
_A11Y_SVC = "Landroid/accessibilityservice/AccessibilityService;"
_TEL_MGR = "Landroid/telephony/TelephonyManager;"

RULES: tuple[ApiRule, ...] = (
    ApiRule("sms_send", ApiCategory.sms, "sends SMS",
            calls=((_SMS_MGR, "sendTextMessage|sendMultipartTextMessage|sendDataMessage"),)),
    ApiRule("sms_read_incoming", ApiCategory.sms, "parses incoming SMS",
            calls=((_SMS_MSG, "createFromPdu|getMessageBody|getDisplayMessageBody|getOriginatingAddress"),
                   ("Landroid/provider/Telephony$Sms$Intents;", "getMessagesFromIntent"))),
    ApiRule("sms_inbox_query", ApiCategory.sms, "reads the SMS store",
            strings=("content://sms", "content://sms/inbox", "content://sms/sent")),
    ApiRule("a11y_service", ApiCategory.accessibility, "implements an accessibility service",
            subclass_of=(_A11Y_SVC,)),
    ApiRule("a11y_actions", ApiCategory.accessibility, "acts on other apps' UI",
            calls=(("Landroid/view/accessibility/AccessibilityNodeInfo;", "performAction"),
                   (_A11Y_SVC, "performGlobalAction|dispatchGesture"))),
    ApiRule("overlay_window", ApiCategory.overlay, "adds windows via WindowManager",
            calls=(("Landroid/view/WindowManager;", "addView"),)),
    ApiRule("overlay_permission", ApiCategory.overlay, "checks/requests draw-over-apps",
            calls=(("Landroid/provider/Settings;", "canDrawOverlays"),),
            strings=("android.settings.action.MANAGE_OVERLAY_PERMISSION",)),
    ApiRule("http_client", ApiCategory.network, "opens HTTP connections",
            calls=(("Ljava/net/URL;", "openConnection"),)),
    ApiRule("okhttp", ApiCategory.network, "uses OkHttp",
            calls=(("Lokhttp3/OkHttpClient;", "newCall|newWebSocket"),)),
    ApiRule("raw_socket", ApiCategory.network, "opens raw sockets",
            calls=(("Ljava/net/Socket;", "<init>"),)),
    ApiRule("device_identifiers", ApiCategory.telephony, "reads device/SIM identifiers",
            calls=((_TEL_MGR, "getDeviceId|getImei|getMeid|getSubscriberId|getSimSerialNumber|getLine1Number"),)),
    ApiRule("js_bridge", ApiCategory.webview, "exposes Java objects to WebView JavaScript",
            calls=(("Landroid/webkit/WebView;", "addJavascriptInterface"),)),
    ApiRule("js_enabled", ApiCategory.webview, "enables WebView JavaScript",
            calls=(("Landroid/webkit/WebSettings;", "setJavaScriptEnabled"),)),
    ApiRule("cipher", ApiCategory.crypto, "uses javax.crypto ciphers",
            calls=(("Ljavax/crypto/Cipher;", "getInstance|doFinal"),)),
)

_MAX_LOCATIONS = 5


@dataclass
class ApiUsageObservation:
    category: ApiCategory
    marker: str               # rule id
    context: str              # human-readable where/how
    suspicious: bool = False
    evidence: str = "api_call"            # api_call | string_ref | subclass
    locations: list[str] = field(default_factory=list)


@dataclass
class ApiUsageReport:
    observations: list[ApiUsageObservation] = field(default_factory=list)
    status: str = "observed"              # observed | unavailable
    reason: str = "API calls resolved from DEX bytecode cross-references."
    # rule id -> call sites ignored because they are in third-party library code
    library_call_sites_ignored: dict[str, int] = field(default_factory=dict)
    # rule id -> why app-code observations were dropped by a manifest gate
    gated_out: dict[str, str] = field(default_factory=dict)

    def categories(self) -> set[ApiCategory]:
        return {o.category for o in self.observations}

    def own(self) -> list["ApiUsageObservation"]:
        """Observations with at least one call site in the app's own code. analyze()
        already drops library-only ones; this also covers hand-built reports."""
        return [o for o in self.observations
                if not o.locations or any(not is_library(loc) for loc in o.locations)]


def analyze(index: DexIndex, app_category: str | None, manifest=None) -> ApiUsageReport:
    """Find the app's own call sites of each rule's APIs. `app_category` drives
    `suspicious`; `manifest` (ManifestFacts) enables the accessibility/overlay
    gates (None: no gating, e.g. for a bare DEX)."""
    if not index.available:
        return ApiUsageReport(status="unavailable",
                              reason=f"API usage not analysed: {index.error}.")
    report = ApiUsageReport()
    hits = {}
    for rule in RULES:
        hit = _match(index, rule)
        if hit is None:
            continue
        evidence, locations = hit
        own = [loc for loc in locations if not is_library(loc)]
        if len(own) < len(locations):
            report.library_call_sites_ignored[rule.rule_id] = len(locations) - len(own)
        if own:
            hits[rule.rule_id] = (rule, evidence, own)
    _apply_manifest_gates(hits, manifest, report)
    if report.library_call_sites_ignored:
        report.reason += (f" Ignored {sum(report.library_call_sites_ignored.values())} call site(s) in "
                          "third-party library code.")
    for rid, why in report.gated_out.items():
        report.reason += f" Dropped {rid}: {why}."
    for rule in RULES:
        if rule.rule_id not in hits:
            continue
        _, evidence, locations = hits[rule.rule_id]
        shown = ", ".join(locations[:_MAX_LOCATIONS])
        more = f" (+{len(locations) - _MAX_LOCATIONS} more)" if len(locations) > _MAX_LOCATIONS else ""
        report.observations.append(ApiUsageObservation(
            category=rule.category,
            marker=rule.rule_id,
            context=f"{rule.description}: {shown}{more}",
            suspicious=_is_suspicious_for_category(rule.category, app_category),
            evidence=evidence,
            locations=locations,
        ))
    return report


def _manifest_readable(manifest) -> bool:
    return manifest is not None and bool(getattr(manifest, "package_name", None))


def _apply_manifest_gates(hits: dict, manifest, report: ApiUsageReport) -> None:
    if manifest is None:
        return
    if not _manifest_readable(manifest):
        if any(hits.get(r) for r in ("a11y_service", "a11y_actions", "overlay_window", "overlay_permission")):
            report.reason += (" Accessibility/overlay manifest gates not checked: the manifest "
                              "is unreadable, so those observations are kept.")
        return
    declared_a11y = any(c.kind == "service" and c.permission == BIND_ACCESSIBILITY_SERVICE
                        for c in manifest.components)
    own_a11y_class = "a11y_service" in hits          # the app's own class extends AccessibilityService
    if not (declared_a11y or own_a11y_class):
        for rid in ("a11y_actions",):
            if hits.pop(rid, None):
                report.gated_out[rid] = ("no accessibility service is declared with "
                                         "BIND_ACCESSIBILITY_SERVICE and no app class extends "
                                         "AccessibilityService")
    if SYSTEM_ALERT_WINDOW not in set(manifest.permissions):
        for rid in ("overlay_window", "overlay_permission"):
            if hits.pop(rid, None):
                report.gated_out[rid] = "the app doesn't request SYSTEM_ALERT_WINDOW"


def _match(index: DexIndex, rule: ApiRule) -> tuple[str, list[str]] | None:
    locations: set[str] = set()
    evidence = None
    for cls, method in rule.calls:
        found = index.callers_of(cls, method)
        if found:
            locations.update(found)
            evidence = evidence or "api_call"
    if rule.strings:
        for users in index.string_users(list(rule.strings)).values():
            locations.update(users)
            evidence = evidence or "string_ref"
    for parent in rule.subclass_of:
        subs = index.subclasses_of(parent)
        if subs:
            locations.update(subs)
            evidence = evidence or "subclass"
    if not locations:
        return None
    return evidence or "api_call", sorted(locations)


# Category-normalcy table: which API categories are abnormal for an app category.
# It mirrors the SOURCED ANOMALOUS_FOR edges of the knowledge graph
# (data/knowledge_graph/seed_ontology.yaml; SmsInterception -> sms,
# AccessibilityAbuse -> accessibility); tests/test_knowledge_graph.py checks they
# agree. SMS is NOT abnormal for Banking (OTP auto-read, UPI device binding), and
# overlay/telephony have no source for any category yet.
_ANOMALOUS = {
    "banking": {ApiCategory.accessibility},
    "wallpaper": {ApiCategory.sms, ApiCategory.accessibility},
    "game": {ApiCategory.sms, ApiCategory.accessibility},
}


def _is_suspicious_for_category(category: ApiCategory, app_category: str | None) -> bool:
    if not app_category:
        return False
    return category in _ANOMALOUS.get(app_category.lower(), set())
