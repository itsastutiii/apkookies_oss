"""Knowledge graph: every category edge is sourced; its score bonus is experimental and off."""
from __future__ import annotations

import pytest
import yaml

from backend.scoring import knowledge_graph as kgm
from backend.scoring.risk_score import score_static
from backend.static_analysis import api_usage
from tests.test_scoring import make_bundle

A11Y = ["android.permission.BIND_ACCESSIBILITY_SERVICE"]


def test_every_category_edge_has_a_source():
    caps = yaml.safe_load(kgm._ONTOLOGY.read_text())["capabilities"]
    for cap, spec in caps.items():
        for key in ("normal_for", "anomalous_for"):
            for e in spec.get(key) or []:
                assert isinstance(e, dict) and e["source"].strip(), (cap, key, e)


def test_an_edge_without_a_source_is_rejected(tmp_path):
    bad = tmp_path / "o.yaml"
    bad.write_text("capabilities:\n  X:\n    enabled_by: [p]\n    anomalous_for: [Banking]\n")
    with pytest.raises(ValueError, match="has no source"):
        kgm.InMemoryKnowledgeGraph(bad)


def test_ungrounded_banking_edges_are_gone():
    kg = kgm.default_graph()
    for perms in (["android.permission.READ_SMS", "android.permission.RECEIVE_SMS"],
                  ["android.permission.CAMERA", "android.permission.RECORD_AUDIO",
                   "android.permission.ACCESS_FINE_LOCATION"],
                  ["android.permission.SYSTEM_ALERT_WINDOW"]):
        assert all(c.context != "ANOMALOUS_FOR" for c in kg.derive_capabilities(perms, "Banking")), perms


def test_kg_boost_is_off_by_default_and_context_stays_in_the_report(monkeypatch):
    r = score_static(make_bundle("Banking", A11Y))
    assert "kg_context" not in {s.step for s in r.breakdown}
    assert any("Context (not scored)" in f for f in r.contributing_factors)
    assert "AccessibilityAbuse" in r.capabilities
    import backend.scoring.risk_score as rs
    cfg = rs.thresholds()
    monkeypatch.setattr(rs, "thresholds", lambda: {**cfg, "kg_context_boost": True})
    on = score_static(make_bundle("Banking", A11Y), mode="rules")      # base 0: exact delta
    assert {s.step: s.delta for s in on.breakdown}["kg_context"] == pytest.approx(0.08)


def test_api_suspicion_table_mirrors_the_sourced_edges():
    kg = kgm.default_graph()
    cap_to_api = {"SmsInterception": api_usage.ApiCategory.sms,
                  "AccessibilityAbuse": api_usage.ApiCategory.accessibility}
    expected: dict[str, set] = {}
    for cap, api in cap_to_api.items():
        for cat in kgm.edge_categories(kg._caps[cap], "anomalous_for"):
            expected.setdefault(cat.lower(), set()).add(api)
    assert {k: v for k, v in api_usage._ANOMALOUS.items()} == expected
