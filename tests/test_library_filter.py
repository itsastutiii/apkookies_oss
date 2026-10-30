"""API-usage detection counts only the app's own code, and accessibility/overlay
need the manifest to back them (a genuine bank app scored 0.90 from SDK calls)."""
from __future__ import annotations

from backend.static_analysis import api_usage
from backend.static_analysis.libraries import is_library
from backend.static_analysis.manifest import Component, ManifestFacts

APP = "Lcom/demo/bank/Ui;->show"
A11Y_PERM = "android.permission.BIND_ACCESSIBILITY_SERVICE"
SAW = "android.permission.SYSTEM_ALERT_WINDOW"


class FakeIndex:
    """Stands in for DexIndex: call sites per (class, method-regex) / string / superclass."""
    available = True

    def __init__(self, calls=None, strings=None, subclasses=None):
        self.calls, self.strings, self.subclasses = calls or {}, strings or {}, subclasses or {}

    def callers_of(self, cls, method):
        return sorted({loc for (c, m), locs in self.calls.items() if c == cls and m == method
                       for loc in locs})

    def string_users(self, strings):
        return {s: self.strings[s] for s in strings if s in self.strings}

    def subclasses_of(self, cls):
        return self.subclasses.get(cls, [])


OVERLAY = ("Landroid/view/WindowManager;", "addView")
A11Y_ACT = ("Landroid/view/accessibility/AccessibilityNodeInfo;", "performAction")
A11Y_SVC = "Landroid/accessibilityservice/AccessibilityService;"
SMS_SEND = ("Landroid/telephony/SmsManager;", "sendTextMessage|sendMultipartTextMessage|sendDataMessage")


def _manifest(perms=(), a11y_service=False):
    comps = [Component(name="com.demo.bank.A11y", kind="service", permission=A11Y_PERM)] if a11y_service else []
    return ManifestFacts(package_name="com.demo.bank", permissions=list(perms), components=comps)


def _markers(rep):
    return {o.marker for o in rep.observations}


def test_prefix_list():
    for loc in ("Landroidx/core/view/ViewCompat;->x", "Lcom/google/android/gms/a;->b",
                "Lokhttp3/OkHttpClient;->newCall", "Lio/flutter/embedding/X;->y", "Lkotlinx/a;->b"):
        assert is_library(loc), loc
    assert not is_library(APP) and not is_library("Lcom/googlex/evil/A;->b")


def test_library_call_sites_are_ignored_and_counted():
    idx = FakeIndex(calls={OVERLAY: ["Landroidx/appcompat/widget/Popup;->show"],
                           SMS_SEND: ["Lcom/google/android/gms/x;->y", APP]})
    rep = api_usage.analyze(idx, None, _manifest([SAW]))
    assert "overlay_window" not in _markers(rep)                     # only AndroidX called it
    sms = next(o for o in rep.observations if o.marker == "sms_send")
    assert sms.locations == [APP]                                     # library site dropped
    assert rep.library_call_sites_ignored == {"overlay_window": 1, "sms_send": 1}
    assert "Ignored 2 call site(s) in third-party library code" in rep.reason


def test_overlay_needs_system_alert_window_and_own_code():
    idx = FakeIndex(calls={OVERLAY: [APP]})
    assert "overlay_window" not in _markers(api_usage.analyze(idx, None, _manifest()))
    rep = api_usage.analyze(idx, None, _manifest())
    assert "SYSTEM_ALERT_WINDOW" in rep.gated_out["overlay_window"]
    assert "overlay_window" in _markers(api_usage.analyze(idx, None, _manifest([SAW])))


def test_accessibility_needs_a_declared_service_or_own_subclass():
    idx = FakeIndex(calls={A11Y_ACT: [APP]})
    assert "a11y_actions" not in _markers(api_usage.analyze(idx, None, _manifest()))
    assert "a11y_actions" in _markers(api_usage.analyze(idx, None, _manifest(a11y_service=True)))
    own_svc = FakeIndex(calls={A11Y_ACT: [APP]}, subclasses={A11Y_SVC: ["Lcom/demo/bank/Svc;"]})
    assert {"a11y_service", "a11y_actions"} <= _markers(api_usage.analyze(own_svc, None, _manifest()))
    # A library class extending AccessibilityService is not the app's own service.
    lib_svc = FakeIndex(calls={A11Y_ACT: [APP]}, subclasses={A11Y_SVC: ["Landroidx/core/A11y;"]})
    assert not _markers(api_usage.analyze(lib_svc, None, _manifest())) & {"a11y_service", "a11y_actions"}


def test_unreadable_manifest_keeps_observations():
    idx = FakeIndex(calls={OVERLAY: [APP], A11Y_ACT: [APP]})
    rep = api_usage.analyze(idx, None, ManifestFacts())               # no package name: unreadable
    assert {"overlay_window", "a11y_actions"} <= _markers(rep) and "not checked" in rep.reason


def test_rules_ignore_hand_built_library_only_observations():
    from backend.scoring import rules_engine
    from backend.static_analysis.api_usage import ApiCategory, ApiUsageObservation
    from tests.test_scoring import make_bundle
    lib = [ApiUsageObservation(ApiCategory.accessibility, "a11y_actions", "x", locations=["Landroidx/a;->b"]),
           ApiUsageObservation(ApiCategory.overlay, "overlay_window", "x", locations=["Lcom/google/c;->d"])]
    assert not [h for h in rules_engine.evaluate(make_bundle(None, [], lib)) if h.rule_id.startswith("R002")]
