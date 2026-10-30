"""Optional Quark-Engine integration.

Always runs: disabled/not-installed/not-configured paths and report conversion.
Real-rules tests run only when quark-engine is installed AND QUARK_RULES_DIR
points at the quark-rules checkout (docs/QUARK.md); otherwise they skip.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.static_analysis import quark_rules

FIX = Path(__file__).parent / "fixtures" / "dex"
ROOT = Path(__file__).resolve().parents[1]


def _cfg(monkeypatch, rules_dir: str, min_conf: int = 80):
    monkeypatch.setattr(quark_rules, "_settings",
                        lambda: SimpleNamespace(quark_rules_dir=rules_dir, quark_min_confidence=min_conf))


def test_disabled_without_rules_dir(monkeypatch):
    _cfg(monkeypatch, "")
    rep = quark_rules.analyze(FIX / "suspicious.dex")
    assert rep.status == "disabled" and "QUARK_RULES_DIR" in rep.reason and not rep.behaviours


def test_disabled_when_rules_dir_missing(monkeypatch, tmp_path):
    _cfg(monkeypatch, str(tmp_path / "nope"))
    assert quark_rules.analyze(FIX / "suspicious.dex").status == "disabled"


def test_disabled_when_not_installed(monkeypatch, tmp_path):
    _cfg(monkeypatch, str(tmp_path))
    monkeypatch.setitem(sys.modules, "quark.report", None)  # import -> ImportError
    rep = quark_rules.analyze(FIX / "suspicious.dex")
    assert rep.status == "disabled" and "not installed" in rep.reason


def test_json_report_conversion_filters_and_sorts():
    report = {"threat_level": "High Risk", "total_score": 3, "crimes": [
        {"rule": "a.json", "crime": "weak", "confidence": "60%", "score": 2.0, "label": ["x"]},
        {"rule": "b.json", "crime": "seq", "confidence": "80%", "score": 1.0, "label": ["sms"]},
        {"rule": "c.json", "crime": "flow", "confidence": "100%", "score": 0.5, "label": ["sms"]},
    ]}
    rep = quark_rules.from_json_report(report, min_confidence=80)
    assert rep.status == "observed" and rep.threat_level == "High Risk"
    assert [b.rule for b in rep.behaviours] == ["c.json", "b.json"]


def test_behaviour_fields_match_json_schema():
    from schemas.report import Behaviour

    schema = json.loads((ROOT / "schemas/report.schema.json").read_text(encoding="utf-8"))
    items = schema["properties"]["static_findings"]["properties"]["behaviours"]["items"]
    assert set(items["properties"]) == set(Behaviour.model_fields)


RULES = os.environ.get("QUARK_RULES_DIR", "")
real = pytest.mark.skipif(
    not (RULES and Path(RULES).is_dir()) or importlib.util.find_spec("quark") is None,
    reason="needs quark-engine + QUARK_RULES_DIR",
)


@real
def test_real_rules_on_suspicious_dex(monkeypatch):
    _cfg(monkeypatch, RULES)
    rep = quark_rules.analyze(FIX / "suspicious.dex")
    assert rep.status == "observed"
    crimes = {b.crime for b in rep.behaviours}
    assert "Send a SMS message" in crimes
    assert any("accessibility" in " ".join(b.labels) for b in rep.behaviours)


@real
def test_real_rules_on_benign_dex(monkeypatch):
    _cfg(monkeypatch, RULES)
    rep = quark_rules.analyze(FIX / "benign.dex")
    assert rep.status == "observed"
    labels = {lab for b in rep.behaviours for lab in b.labels}
    assert not labels & {"sms", "accessibility service", "calllog"}
