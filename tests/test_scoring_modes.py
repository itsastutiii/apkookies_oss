"""Scoring modes: rules (transparent, no ML) | model (shipped, experimental) | retrained."""
from __future__ import annotations

import pytest

from backend.common import provenance
from backend.scoring import modes
from backend.scoring.risk_score import score_static
from backend.static_analysis.api_usage import ApiCategory, ApiUsageObservation
from tests.test_scoring import make_bundle

SMS_PERMS = ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
             "android.permission.INTERNET"]


def _sums(result):
    return abs(sum(s.delta for s in result.breakdown) - result.score) < 1e-9


def test_default_mode_is_model_and_reports_it(monkeypatch):
    monkeypatch.delenv(modes.ENV_VAR, raising=False)
    assert modes.current_mode() == "model"
    r = score_static(make_bundle("Productivity", []))
    assert r.scoring_mode == "model" and r.breakdown[0].step == "model" and _sums(r)


def test_rules_mode_uses_no_model_and_explains_every_point():
    r = score_static(make_bundle("Productivity", SMS_PERMS), mode="rules")
    assert r.scoring_mode == "rules"
    assert r.breakdown[0].step == "no_model" and r.breakdown[0].delta == 0
    assert "model_probability" not in r.components
    assert all(s.step != "model" for s in r.breakdown)
    steps = {s.step: s for s in r.breakdown}
    assert steps["evidence:sensitive_permissions"].delta == pytest.approx(0.08)   # 2 × 0.04
    assert steps["rule:R001_SMS_INTERCEPT_NONCOMM"].delta == pytest.approx(0.05)  # stage-1 weight
    assert r.score == pytest.approx(0.13) and _sums(r)
    assert "transparent_weights" in r.decision_path


def test_rules_mode_keeps_a_plain_app_low_where_the_model_does_not():
    # The shipped model scores SMS permissions high on their own (see ARCHITECTURE.md);
    # transparent scoring of the same permissions in a messaging app stays in "allow".
    b = make_bundle("Communication", SMS_PERMS)
    assert score_static(b, mode="rules").score < 0.25
    assert score_static(b, mode="model").score >= 0.55          # block on the default policy


def test_rules_mode_caps_each_kind_of_evidence():
    api = [ApiUsageObservation(ApiCategory.sms, f"m{i}", "x", suspicious=True) for i in range(10)]
    r = score_static(make_bundle("Wallpaper", [], api), mode="rules")
    assert {s.step: s.delta for s in r.breakdown}["evidence:suspicious_api_use"] == pytest.approx(0.15)


def test_mode_from_config_and_environment(monkeypatch):
    monkeypatch.setenv(modes.ENV_VAR, "rules")
    assert modes.current_mode() == "rules"
    assert score_static(make_bundle(None, [])).scoring_mode == "rules"
    monkeypatch.setenv(modes.ENV_VAR, "magic")
    with pytest.raises(modes.ScoringModeError, match="unknown scoring mode"):
        modes.current_mode()


def test_retrained_mode_refuses_to_run_without_its_models(monkeypatch, tmp_path):
    monkeypatch.setattr(modes, "_MODELS", tmp_path)          # no ml/models/retrained/ here
    with pytest.raises(modes.ScoringModeError, match="retrained"):
        score_static(make_bundle(None, []), mode="retrained")


def test_mode_is_part_of_verdict_provenance():
    rules, model = provenance.current(mode="rules"), provenance.current(mode="model")
    assert rules["scoring_mode"] == "rules" and rules["model_files"] == {}
    assert set(model["model_files"]) == {"rgcn.pt", "bayesian.joblib", "xgboost.json", "xgboost.meta.json"}
    # Switching modes makes remembered verdicts stale, so they're re-checked.
    assert rules["fingerprint"] != model["fingerprint"]


def test_reports_carry_the_mode(tmp_path, monkeypatch):
    import asyncio

    from backend.hashing.lookup import HashLookupService
    from backend.hashing.verdict_store import VerdictStore
    from backend.orchestration import pipeline
    from schemas.report import InputType
    from tests.test_category import _apk

    db = tmp_path / "verdicts.sqlite3"
    monkeypatch.setattr(pipeline, "_lookup", HashLookupService(store=VerdictStore(db)))
    monkeypatch.setenv(modes.ENV_VAR, "rules")
    data = _apk(tmp_path, "suspicious").read_bytes()
    first = asyncio.run(pipeline.analyze(InputType.apk, data=data, filename="x.apk")).report
    assert first.risk.scoring_mode == "rules" and first.verdict.provenance["scoring_mode"] == "rules"
    again = asyncio.run(pipeline.analyze(InputType.apk, data=data, filename="x.apk")).report
    assert again.risk.breakdown[0].step == "remembered_verdict" and again.risk.scoring_mode == "rules"
    # Switch back to the model and restart (the store reads provenance at start-up):
    # the rules-mode verdict is stale, so the file is re-analysed.
    monkeypatch.setenv(modes.ENV_VAR, "model")
    monkeypatch.setattr(pipeline, "_lookup", HashLookupService(store=VerdictStore(db)))
    third = asyncio.run(pipeline.analyze(InputType.apk, data=data, filename="x.apk")).report
    assert third.risk.scoring_mode == "model"
    assert third.verdict.stale_previous_verdict == first.verdict.label.value
