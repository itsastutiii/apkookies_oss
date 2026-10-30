"""ATT&CK Mobile mapping against the pinned official data."""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from backend.reporting import mitre_mapping as mm
from backend.static_analysis.anti_analysis import MITRE_MAP

ROOT = Path(__file__).resolve().parents[1]


def _all_referenced_ids() -> set[str]:
    ids = set(MITRE_MAP.values()) | set(mm.RUNTIME_BEHAVIOR_TECHNIQUES.values())
    for tids in mm.API_RULE_TECHNIQUES.values():
        ids |= set(tids)
    onto = yaml.safe_load((ROOT / "data/knowledge_graph/seed_ontology.yaml").read_text())
    for spec in onto["capabilities"].values():
        ids |= set(spec.get("mitre", []))
    return ids


def test_pinned_data_provenance():
    d = mm.attack_data()
    assert d["domain"] == "mobile-attack" and d["attack_version"] == "20.0"
    assert len(d["source_sha256"]) == 64 and d["source_url"].endswith("mobile-attack-20.0.json")
    active_parents = [t for t in d["techniques"].values()
                      if not (t["deprecated"] or t["revoked"]) and not t["subtechnique_of"]]
    assert len(active_parents) == 78


def test_every_referenced_technique_is_active_mobile():
    techniques = mm.attack_data()["techniques"]
    for tid in sorted(_all_referenced_ids()):
        assert tid in techniques, f"{tid} is not an ATT&CK Mobile technique"
        assert not (techniques[tid]["deprecated"] or techniques[tid]["revoked"]), tid


def test_enterprise_ids_are_gone():
    assert not {"T1622", "T1480"} & _all_referenced_ids()


def test_resolve_names_from_data():
    t = mm.resolve("T1636.004", ["ev-1"], "api_call")
    assert t.technique_name == "Protected User Data: SMS Messages"
    assert t.tactic == "Collection" and t.attack_version == "20.0"
    assert mm.resolve("T9999").technique_name.startswith("Not in ATT&CK Mobile")


def test_heatmap_keeps_strongest_evidence_and_all_refs():
    hb = mm.HeatmapBuilder()
    hb.add("T1453", "ev-perm", "permission")
    hb.add("T1453", "ev-code", "api_call")
    hb.add("T1453", "ev-code", "api_call")
    hb.add("T1582", "ev-perm", "permission")
    out = {t.technique_id: t for t in hb.build()}
    assert out["T1453"].evidence_strength == "api_call"
    assert out["T1453"].evidence_refs == ["ev-perm", "ev-code"]
    assert out["T1582"].evidence_strength == "permission"


def test_known_banking_families_present():
    malware = mm.attack_data()["malware"]
    assert {"S1067", "S0422", "S0480"} <= set(malware)  # FluBot, Anubis, Cerberus
    assert "T1636.004" in malware["S1067"]["techniques"]


def test_mitre_fields_match_json_schema():
    from schemas.report import MitreTechnique

    schema = json.loads((ROOT / "schemas/report.schema.json").read_text(encoding="utf-8"))
    assert set(schema["properties"]["mitre_attack"]["items"]["properties"]) == set(
        MitreTechnique.model_fields)


def test_rule_implicated_api_use_reaches_the_heatmap(tmp_path, monkeypatch):
    """The SMS/accessibility trojan fixture has no category, so no API use is
    "suspicious" by the category table; R002 fired on it, so its calls are mapped."""
    import asyncio

    from backend.hashing.lookup import HashLookupService
    from backend.hashing.verdict_store import VerdictStore
    from backend.orchestration import pipeline
    from schemas.report import InputType
    from tests.test_category import _apk

    monkeypatch.setattr(pipeline, "_lookup", HashLookupService(store=VerdictStore(":memory:")))
    data = _apk(tmp_path, "suspicious").read_bytes()
    report = asyncio.run(pipeline.analyze(InputType.apk, data=data, filename="x.apk")).report
    assert "R002_A11Y_OVERLAY" in {h.rule_id for h in report.risk.rules_triggered}
    techniques = {t.technique_id: t for t in report.mitre_attack}
    for tid in ("T1453", "T1417.002", "T1636.004", "T1582"):
        assert tid in techniques and techniques[tid].evidence_strength == "api_call", tid
    assert any(e.summary.startswith("Rule-implicated") for e in report.evidence)
