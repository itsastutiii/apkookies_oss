"""Bytecode cross-reference helpers + code_intel, on real (benign, source-built) DEX fixtures.

tests/fixtures/dex/*.dex are compiled from tests/fixtures/dex_src (build.sh).
They are bare DEX files, not APKs, and the code in them is never executed.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from backend.static_analysis import code_intel, dex_analysis

FIX = Path(__file__).parent / "fixtures" / "dex"


def load(name: str) -> dex_analysis.DexIndex:
    return dex_analysis.build(b"", dex_entries=[("classes.dex", (FIX / f"{name}.dex").read_bytes())])


@pytest.fixture(scope="module")
def bad() -> dex_analysis.DexIndex:
    return load("suspicious")


@pytest.fixture(scope="module")
def good() -> dex_analysis.DexIndex:
    return load("benign")


def test_index_builds(bad, good):
    assert bad.available and good.available


def test_callers_found_only_where_api_is_called(bad, good):
    assert bad.callers_of("Landroid/telephony/SmsManager;", "sendTextMessage") == [
        "Lcom/fixture/bad/SmsSpy;->forward"]
    # benign.dex mentions "SmsManager" in log text but never calls it
    assert good.callers_of("Landroid/telephony/SmsManager;", "sendTextMessage") == []


def test_inherited_framework_call_counts(bad):
    assert bad.callers_of("Landroid/accessibilityservice/AccessibilityService;",
                          "performGlobalAction") == ["Lcom/fixture/bad/A11y;->onAccessibilityEvent"]


def test_strings_match_exactly_not_as_substrings(bad, good):
    assert "goldfish" in bad.string_users(["goldfish"])
    assert good.string_users(["goldfish", "/system/xbin/su"]) == {}  # only inside a sentence


def test_static_field_reads(bad, good):
    assert bad.static_field_readers("Landroid/os/Build;", ["FINGERPRINT"]) == [
        "Lcom/fixture/bad/Evasion;->isEmulator"]
    assert good.static_field_readers("Landroid/os/Build;", ["MODEL"]) == [
        "Lcom/fixture/good/Analytics;->deviceInfo"]


def test_unavailable_when_no_dex():
    ix = dex_analysis.build(b"not a zip")
    assert not ix.available and ix.error


def test_code_intel_single_pass_dedups_strings(tmp_path):
    blob = (FIX / "suspicious.dex").read_bytes()
    rep = code_intel.analyze(tmp_path / "unused.apk",
                             dex_entries=[("classes.dex", blob), ("classes2.dex", blob)])
    assert rep.dex_strings == sorted(set(rep.dex_strings))
    assert set(rep.entropy_by_dex) == {"classes.dex", "classes2.dex"}


def _rules(report):
    return {o.marker: o for o in report.observations}


def test_api_usage_from_call_sites(bad):
    from backend.static_analysis import api_usage

    rep = api_usage.analyze(bad, app_category="banking")
    obs = _rules(rep)
    assert rep.status == "observed"
    assert {"sms_send", "sms_read_incoming", "sms_inbox_query", "a11y_service", "a11y_actions",
            "overlay_window", "overlay_permission", "js_bridge", "js_enabled"} <= set(obs)
    assert obs["sms_send"].locations == ["Lcom/fixture/bad/SmsSpy;->forward"]
    assert obs["sms_inbox_query"].evidence == "string_ref"
    assert obs["a11y_service"].evidence == "subclass"
    assert not obs["sms_send"].suspicious   # SMS is normal for bank apps (OTP, UPI device binding)
    assert obs["a11y_service"].suspicious   # accessibility: Play policy, sourced KG edge
    assert "device_identifiers" not in obs  # getSimCountryIso is not an identifier read


def test_api_usage_ignores_decoy_text(good):
    from backend.static_analysis import api_usage

    rep = api_usage.analyze(good, app_category="banking")
    assert set(_rules(rep)) == {"http_client"}


def test_api_usage_unavailable_is_reported():
    from backend.static_analysis import api_usage

    rep = api_usage.analyze(dex_analysis.build(b"nope"), None)
    assert rep.status == "unavailable" and rep.observations == []


def _techniques(report):
    return {f.technique: f for f in report.findings}


def test_anti_analysis_from_bytecode(bad):
    from backend.static_analysis import anti_analysis as aa
    from backend.static_analysis.manifest import Component, ManifestFacts

    manifest = ManifestFacts(package_name="x", components=[
        Component(name="Lcom/fixture/bad/Boot;", kind="receiver",
                  intent_filters=["android.intent.action.BOOT_COMPLETED"])])
    found = _techniques(aa.analyze(bad, manifest))
    emu = found[aa.Technique.EMULATOR_DETECTION]
    assert emu.locations == ["Lcom/fixture/bad/Evasion;->isEmulator"]
    assert emu.evidence == "field_read+string" and "/dev/socket/qemud" in emu.markers_hit
    assert found[aa.Technique.DEBUGGER_DETECTION].locations == ["Lcom/fixture/bad/Evasion;->isDebugged"]
    assert found[aa.Technique.ROOT_DETECTION].common_in_benign
    assert "Lcom/fixture/bad/Evasion;->stall" in found[aa.Technique.TIMING_STALL].locations
    gating = found[aa.Technique.TRIGGER_GATING]
    assert "BOOT_COMPLETED receiver" in gating.markers_hit
    assert "Lcom/fixture/bad/Evasion;->simCountry" in gating.locations


def test_anti_analysis_ignores_decoys_and_plain_build_reads(good):
    """benign.dex reads Build.MODEL and mentions goldfish/su in log text: no findings."""
    from backend.static_analysis import anti_analysis as aa

    assert aa.analyze(good).findings == []
