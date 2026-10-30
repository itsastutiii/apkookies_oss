"""Benign firing rates: a rule above ~1% on benign apps can't be a hard override."""
from __future__ import annotations

import json
from pathlib import Path

from backend.scoring import rules_engine
from ml.eval import benign_firing_rates as bfr

RESULTS = Path(__file__).resolve().parents[1] / "ml" / "results" / "benign_firing_rates.json"
SMS = ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.INTERNET"]


def test_measurement_on_synthetic_rows():
    rows = [(SMS, "benign"), (["android.permission.INTERNET"], "benign"),
            (SMS + ["android.permission.CAMERA"], "malicious")]
    r = bfr.measure_permission_rows(rows)
    assert r["n"] == {"benign": 2, "malicious": 1}
    assert r["rules"]["benign"]["Banking"]["R001_SMS_INTERCEPT_NONCOMM"] == {"apps": 1, "rate": 0.5}
    assert r["rules"]["benign"]["None"] == {}                       # R001 needs a known category
    assert r["kg_capabilities"]["benign"]["SmsInterception"]["rate"] == 0.5
    assert all(v["allowed"] for v in r["hard_override_check"].values())


def test_a_frequent_hard_rule_is_flagged(monkeypatch):
    monkeypatch.setattr(rules_engine, "HARD_RULES", rules_engine.HARD_RULES | {"R001_SMS_INTERCEPT_NONCOMM"})
    r = bfr.check_hard_rules({"rules": {"benign": {"Banking": {
        "R001_SMS_INTERCEPT_NONCOMM": {"apps": 9, "rate": 0.077}}}}})
    assert r["R001_SMS_INTERCEPT_NONCOMM (category Banking)"]["allowed"] is False


def test_committed_cicmaldroid_rates_respect_the_hard_override_limit():
    """ml/results/benign_firing_rates.json (CICMalDroid benign, permissions only)."""
    r = json.loads(RESULTS.read_text())
    assert r["n"]["benign"] == 1795
    assert all(v["allowed"] for v in bfr.check_hard_rules(r).values())
    # Permission-only evidence never reaches a hard rule, whatever its rate.
    for cat in r["rules"]["benign"].values():
        assert not set(cat) & rules_engine.HARD_RULES
