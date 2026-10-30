import pytest
from backend.static_analysis import StaticBundle
from backend.static_analysis.manifest import ManifestFacts
from backend.static_analysis.structural import StructuralReport, SigningInfo
from backend.static_analysis.code_intel import CodeIntelReport
from backend.static_analysis.api_usage import ApiUsageReport, ApiUsageObservation, ApiCategory
from backend.static_analysis.ioc_extraction import IOCReport, ExtractedIOC
from backend.static_analysis.anti_analysis import AntiAnalysisReport
from backend.scoring.knowledge_graph import InMemoryKnowledgeGraph
from backend.scoring.risk_score import score_static, severity_for
from backend.scoring import rules_engine


def make_bundle(category=None, permissions=None, api=None, iocs=None):
    manifest = ManifestFacts(permissions=permissions or [], declared_category=category)
    structural = StructuralReport(manifest=manifest, signing=SigningInfo())
    return StaticBundle(structural, CodeIntelReport(), ApiUsageReport(api or []), IOCReport(iocs or []), AntiAnalysisReport())


def test_kg_context_changes_capability_context():
    kg = InMemoryKnowledgeGraph()
    perms = ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS"]
    comm = kg.derive_capabilities(perms, "Communication")
    game = kg.derive_capabilities(perms, "Game")
    bank = kg.derive_capabilities(perms, "Banking")
    assert comm[0].context == "NORMAL_FOR"
    assert game[0].context == "ANOMALOUS_FOR"
    assert bank[0].context == "UNKNOWN"      # no sourced edge: bank apps read SMS for OTPs


def test_kg_subgraph_contains_category_and_typed_context_edge():
    kg = InMemoryKnowledgeGraph()
    g = kg.induced_subgraph(["android.permission.BIND_ACCESSIBILITY_SERVICE"], "Banking")
    assert {n["type"] for n in g["nodes"]} >= {"Permission", "Capability", "AppCategory"}
    assert any(e["rel"] == "ANOMALOUS_FOR" for e in g["edges"])


def test_sms_rule_requires_known_non_communication_category():
    b = make_bundle(None, ["android.permission.READ_SMS", "android.permission.INTERNET"])
    assert rules_engine.evaluate(b) == []
    b = make_bundle("Banking", ["android.permission.READ_SMS", "android.permission.INTERNET"])
    hit = rules_engine.evaluate(b)[0]
    # Permission-only evidence (stage 1): a small weight, never a floor or a block.
    assert (hit.stage, hit.hard_override, hit.min_score, hit.weight) == (1, False, 0.0, 0.05)


def test_sms_rule_is_graded_by_evidence_stage():
    perms = ["android.permission.READ_SMS", "android.permission.INTERNET"]
    read = ApiUsageObservation(ApiCategory.sms, "sms_read_incoming", "x")
    net = ApiUsageObservation(ApiCategory.network, "okhttp", "x")
    api_only = rules_engine.evaluate(make_bundle("Banking", perms, [read]))[0]
    assert (api_only.stage, api_only.min_score, api_only.weight) == (2, 0.0, 0.10)
    combo = rules_engine.evaluate(make_bundle("Banking", perms, [read, net]))[0]
    assert combo.stage == 3 and combo.min_score == rules_engine.WARN_FLOOR and not combo.hard_override


_A11Y_OVERLAY = [ApiUsageObservation(ApiCategory.accessibility, "a11y", "x"),
                 ApiUsageObservation(ApiCategory.overlay, "overlay", "x")]


def _a11y_bundle(category=None, permissions=(), iocs=(), tool=None, strings=(), package="com.demo.app"):
    b = make_bundle(category, list(permissions), list(_A11Y_OVERLAY), list(iocs))
    b.structural.manifest.accessibility_tool_declared = tool
    b.structural.manifest.package_name = package
    b.code_intel.dex_strings = list(strings)
    return b


def _r002(bundle):
    return {h.rule_id: h for h in rules_engine.evaluate(bundle) if h.rule_id.startswith("R002")}


def test_password_manager_like_app_warns_but_never_blocks():
    # Autofill password managers, launchers and screen-dimmers use accessibility +
    # overlay legitimately. With or without a declaration, with or without a known
    # category: warn (sandbox), never a hard block. The `suspicious` flag is False
    # here on purpose: the rule must not depend on the per-category API table.
    from backend.api.dependencies import resolve_action
    from config import thresholds
    cases = [dict(), dict(category="Productivity"), dict(category="Banking"),
             dict(category="Password Manager"), dict(tool=True), dict(tool=False),
             dict(category="accessibility", tool=True)]
    for kw in cases:
        hits = _r002(_a11y_bundle(**kw))
        assert set(hits) == {"R002B_A11Y_OVERLAY_ALONE"}, kw
        hit = hits["R002B_A11Y_OVERLAY_ALONE"]
        assert not hit.hard_override
        for touchpoint in thresholds()["response_policy"]:
            assert resolve_action(hit.min_score, touchpoint) == "warn", (kw, touchpoint)
        assert thresholds()["response_policy"]["default"]["escalate_to_sandbox_between"][0] <= hit.min_score
    # A declaration lowers the floor a little and says so; it doesn't remove the warning.
    declared = _r002(_a11y_bundle(tool=True))["R002B_A11Y_OVERLAY_ALONE"]
    assert declared.min_score < _r002(_a11y_bundle())["R002B_A11Y_OVERLAY_ALONE"].min_score
    assert "isAccessibilityTool" in declared.description
    # One of the two APIs alone is not the pattern.
    assert not _r002(make_bundle(None, [], _A11Y_OVERLAY[:1]))


def test_trojan_like_combination_without_behaviour_evidence_warns_and_sandboxes():
    """Accessibility + overlay + a second signal is stage-3 evidence: warn-level floor plus
    small weights, never a block by itself (only R005 stage 4-5 behaviour or R004 can)."""
    from backend.api.dependencies import resolve_action
    token = ExtractedIOC(type="telegram_token", value="123456789:" + "A" * 35)
    c2_ip = ExtractedIOC(type="ip", value="45.9.148.12")
    second_signals = [
        dict(permissions=["android.permission.RECEIVE_SMS"]),
        dict(iocs=[token]),
        dict(iocs=[c2_ip]),
        dict(strings=["com.sbi.lotusintouch"]),                  # overlay target list
    ]
    for kw in second_signals:
        for declared in (dict(), dict(tool=True, category="accessibility")):   # fakeable
            hits = _r002(_a11y_bundle(**kw, **declared))
            assert set(hits) == {"R002_A11Y_OVERLAY"}, (kw, declared)
            hit = hits["R002_A11Y_OVERLAY"]
            assert not hit.hard_override and hit.stage == 3 and hit.min_score <= rules_engine.WARN_FLOOR
            assert hit.weight == rules_engine.SECOND_SIGNAL_WEIGHT
    many = _a11y_bundle(permissions=["android.permission.RECEIVE_SMS"], iocs=[token, c2_ip],
                        strings=["com.sbi.lotusintouch"])
    hit = _r002(many)["R002_A11Y_OVERLAY"]
    assert hit.weight == rules_engine.SECOND_SIGNAL_CAP                  # capped
    result = score_static(many)
    assert result.needs_dynamic_analysis or result.score > 0.70           # sandbox decides
    # Bank impersonation by package is itself a hard override (R004), independently.
    b = _a11y_bundle()
    b.structural.signing.allowlist.status = "impersonation"
    b.structural.signing.allowlist.detail = "fake bank app"
    b.structural.signing.allowlist.matched_by = "package"
    ids = {h.rule_id: h for h in rules_engine.evaluate(b)}
    assert "R002_A11Y_OVERLAY" in ids and ids["R004_BANK_IMPERSONATION"].hard_override
    assert resolve_action(score_static(b).score, "default") == "block"


def test_stage_4_5_behaviour_is_the_only_behavioural_block():
    from backend.static_analysis.quark_rules import QuarkBehaviour, QuarkReport
    b = _a11y_bundle()
    b.quark = QuarkReport(status="observed", behaviours=[
        QuarkBehaviour("00123.json", "Read SMS messages and send them over the network", 100, 1.0,
                       labels=["sms", "network"])])
    hit = next(h for h in rules_engine.evaluate(b) if h.rule_id == "R005_BEHAVIOUR")
    assert hit.hard_override and hit.stage == 5 and score_static(b).score >= 0.90
    # 60% = only the two APIs are present (stage 3): not enough.
    b.quark.behaviours[0].confidence = 60
    assert not [h for h in rules_engine.evaluate(b) if h.rule_id == "R005_BEHAVIOUR"]
    # A stage-4 behaviour unrelated to fraud doesn't count.
    b.quark.behaviours = [QuarkBehaviour("00001.json", "Get the device's location", 80, 1.0, ["location"])]
    assert not [h for h in rules_engine.evaluate(b) if h.rule_id == "R005_BEHAVIOUR"]


def test_only_allowed_rules_can_be_hard_overrides(monkeypatch):
    def bad(ctx):
        return rules_engine.RuleHit("R999_PERMISSION_BLOCK", "x", hard_override=True, min_score=0.9, stage=1)
    monkeypatch.setattr(rules_engine, "_RULES", [bad])
    with pytest.raises(AssertionError, match="may not be a hard override"):
        rules_engine.evaluate(make_bundle(None, []))


def test_permission_only_evidence_never_sets_a_block_floor():
    perms = ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.INTERNET",
             "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE"]
    b = make_bundle("Banking", perms)
    b.structural.manifest.components.append(__import__("backend.static_analysis.manifest", fromlist=["Component"])
                                            .Component(name="x.A11y", kind="service",
                                                       permission="android.permission.BIND_ACCESSIBILITY_SERVICE"))
    hits = rules_engine.evaluate(b)
    assert hits and all(h.stage == 1 and h.min_score == 0 and not h.hard_override for h in hits)


def test_bank_targets_ignore_the_apps_own_package_and_private_ips():
    assert rules_engine.bank_targets_in(["com.phonepe.app"], "com.phonepe.app") == []
    assert rules_engine.bank_targets_in(["launch com.phonepe.app now"], "x") == ["com.phonepe.app"]
    assert rules_engine.bank_targets_in(["com.phonepe.application"], "x") == []   # different package
    private = ExtractedIOC(type="ip", value="192.168.1.10", is_private=True)
    assert set(_r002(_a11y_bundle(iocs=[private]))) == {"R002B_A11Y_OVERLAY_ALONE"}


def test_accessibility_tool_flag_from_service_config():
    from lxml import etree

    from backend.static_analysis.manifest import accessibility_tool_flag
    ns = 'xmlns:android="http://schemas.android.com/apk/res/android"'

    def cfg(attrs):
        return etree.fromstring(f"<accessibility-service {ns} {attrs}/>")
    assert accessibility_tool_flag([]) is None
    assert accessibility_tool_flag([cfg('android:isAccessibilityTool="true"')]) is True
    assert accessibility_tool_flag([cfg('android:isAccessibilityTool="false"')]) is False
    assert accessibility_tool_flag([cfg(""), cfg('android:isAccessibilityTool="true"')]) is True


def test_context_changes_score():
    perms = ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.INTERNET"]
    low = score_static(make_bundle("Communication", perms))
    high = score_static(make_bundle("Banking", perms))
    assert high.score >= low.score     # R001's stage-1 weight applies outside messaging apps


def test_score_public_contract():
    result = score_static(make_bundle("Communication", []))
    assert 0.0 <= result.score <= 1.0
    assert result.severity == severity_for(result.score)
    assert isinstance(result.components, dict)
    assert result.verdict_label in {"benign", "suspicious", "malicious"}


def test_non_hard_rule_enforces_its_floor_and_still_escalates():
    # R003 (Telegram bot token) is not a hard override, but its 0.40 floor applies;
    # it used to add only +0.05.
    token = ExtractedIOC(type="telegram_token", value="123456789:" + "A" * 35)
    result = score_static(make_bundle(None, [], iocs=[token]))
    hit = next(h for h in result.rules_triggered if h.rule_id == "R003_TELEGRAM_C2")
    assert not hit.hard_override
    assert score_static(make_bundle(None, [])).score < 0.40
    assert result.score >= 0.40
    assert result.needs_dynamic_analysis   # 0.40 is inside the 0.40-0.70 sandbox band


def test_telegram_token_alone_warns_but_never_blocks():
    # A token alone is a soft signal. 0.40 must be "warn" on every
    # touchpoint (none allows at 0.40, none blocks below 0.45).
    from backend.api.dependencies import resolve_action
    from config import thresholds
    token = ExtractedIOC(type="telegram_token", value="123456789:" + "A" * 35)
    hit = next(h for h in score_static(make_bundle(None, [], iocs=[token])).rules_triggered
               if h.rule_id == "R003_TELEGRAM_C2")
    for touchpoint in thresholds()["response_policy"]:
        assert resolve_action(hit.min_score, touchpoint) == "warn", touchpoint


def _assert_ledger_adds_up(result):
    assert result.breakdown and result.breakdown[0].step == "model"
    assert abs(sum(s.delta for s in result.breakdown) - result.score) < 1e-6
    assert abs(result.breakdown[-1].score_after - result.score) < 1e-9


def test_breakdown_explains_the_final_score():
    perms = ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
             "android.permission.INTERNET", "android.permission.SYSTEM_ALERT_WINDOW"]
    for bundle in (make_bundle(None, []), make_bundle("Communication", perms),
                   make_bundle("Banking", perms)):
        _assert_ledger_adds_up(score_static(bundle))

    banking = score_static(make_bundle("Banking", perms))
    steps = {s.step: s for s in banking.breakdown}
    assert "kg_context" not in steps                  # KG boost is experimental and off by default
    r001 = steps["rule:R001_SMS_INTERCEPT_NONCOMM"]
    assert r001.kind == "add" and "adds 0.05" in r001.detail             # permission stage: weight only
    assert "rule:R001_SMS_INTERCEPT_NONCOMM" not in {s.step for s in banking.breakdown if s.kind == "floor"}


def test_breakdown_includes_runtime_evidence():
    class Dyn:
        findings = ["a", "b"]
        overlay_detected_count = 1

    result = score_static(make_bundle(None, []), dynamic=Dyn(), network=[])
    steps = {s.step: s.delta for s in result.breakdown}
    assert steps["runtime_behaviors"] > 0 and steps["runtime_overlays"] > 0
    assert "runtime_network" not in steps    # zero contributions are not listed
    _assert_ledger_adds_up(result)
