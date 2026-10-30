"""Verdict lifecycle: persistence, provenance, analyst override/clear + audit, stale re-checks."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.common import provenance
from backend.hashing import exact_hash
from backend.hashing.clustering import VariantClusterStore
from backend.hashing.content_hash import content_hashes
from backend.hashing.lookup import HashLookupService
from backend.hashing.verdict_store import VerdictStore
from tests.test_content_hashing import ORIGINAL, REZIPPED

SHA_A = exact_hash.hash_bytes(ORIGINAL).sha256
PROV_OLD = {**provenance.current(), "fingerprint": "old-model"}
PROV_NEW = {**provenance.current(), "fingerprint": "new-model"}


def _svc(path=":memory:", prov=PROV_NEW) -> HashLookupService:
    return HashLookupService(store=VerdictStore(path, current_provenance=prov),
                             clusters=VariantClusterStore(similarity_threshold=0.90))


def _variant(svc):
    return svc.lookup(exact_hash.hash_bytes(REZIPPED), content_hashes(REZIPPED))


def test_provenance_is_complete():
    p = provenance.stamp("static")
    assert p["source"] == "static" and p["scoring_version"] == provenance.SCORING_VERSION
    assert set(p["model_files"]) == {"rgcn.pt", "bayesian.joblib", "xgboost.json", "xgboost.meta.json"}
    assert all(p["model_files"].values())          # every shipped model file hashed
    assert "thresholds.yaml" in p["config_files"] and p["fingerprint"] and p["recorded_at"]


def test_fingerprint_changes_with_a_model_file(tmp_path):
    for rel in provenance.MODEL_FILES + provenance.CONFIG_FILES:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_bytes(b"v1")
    before = provenance.current(tmp_path)["fingerprint"]
    (tmp_path / "ml/models/xgboost.json").write_bytes(b"retrained")
    assert provenance.current(tmp_path)["fingerprint"] != before


def test_verdicts_and_variant_matching_survive_restart(tmp_path):
    db = tmp_path / "verdicts.sqlite3"
    _svc(db).record_verdict(SHA_A, "malicious", content_hashes(ORIGINAL), fingerprints=["k1"])
    restarted = _svc(db)
    exact = restarted.lookup(exact_hash.hash_bytes(ORIGINAL), content_hashes(ORIGINAL))
    assert exact.hit and exact.verdict == "malicious" and exact.source == "static"
    assert exact.provenance["fingerprint"] == "new-model"
    assert _variant(restarted).matched_by == "dex_exact"            # DEX index rebuilt
    assert next(restarted.store.active()).fingerprints == ["k1"]    # for certificate reuse


def test_benign_override_is_exact_only_and_stops_inheritance():
    svc = _svc()
    svc.record_verdict(SHA_A, "malicious", content_hashes(ORIGINAL))
    assert _variant(svc).hit
    svc.override(SHA_A, "benign", "asha", "false positive: genuine vendor app, cert verified")
    same = svc.lookup(exact_hash.hash_bytes(ORIGINAL), content_hashes(ORIGINAL))
    assert same.verdict == "benign" and same.source == "analyst"
    assert same.provenance["analyst"] == "asha"
    # The repackaged copy neither inherits "benign" nor the old "malicious".
    assert not _variant(svc).hit


def test_malicious_override_spreads_to_variants():
    svc = _svc()
    svc.record_verdict(SHA_A, "benign", content_hashes(ORIGINAL))
    svc.override(SHA_A, "malicious", "asha", "confirmed dropper")
    assert _variant(svc).verdict == "malicious"


def test_machine_verdict_never_overwrites_analyst():
    svc = _svc()
    svc.override(SHA_A, "benign", "asha", "reviewed")
    svc.record_verdict(SHA_A, "malicious", content_hashes(ORIGINAL), source="sandbox")
    assert svc.store.get(SHA_A).verdict == "benign"


def test_clear_and_audit_log():
    svc = _svc()
    svc.record_verdict(SHA_A, "malicious", content_hashes(ORIGINAL))
    assert svc.clear(SHA_A, "asha", "re-check after allowlist update")
    assert not svc.lookup(exact_hash.hash_bytes(ORIGINAL), content_hashes(ORIGINAL)).hit
    assert not _variant(svc).hit
    assert svc.store.get(SHA_A, include_cleared=True).cleared      # kept for the audit trail
    [entry] = svc.store.history(SHA_A)
    assert (entry["action"], entry["actor"], entry["old_verdict"]) == ("clear", "asha", "malicious")
    with pytest.raises(ValueError):
        svc.override(SHA_A, "benign", "asha", "  ")                 # reason required


def test_stale_verdict_is_rechecked_not_reused(tmp_path):
    db = tmp_path / "v.sqlite3"
    _svc(db, PROV_OLD).record_verdict(SHA_A, "malicious", content_hashes(ORIGINAL))
    retrained = _svc(db, PROV_NEW)
    res = retrained.lookup(exact_hash.hash_bytes(ORIGINAL), content_hashes(ORIGINAL))
    assert not res.hit and res.stale_verdict == "malicious"
    assert not _variant(retrained).hit                 # stale verdicts don't spread
    assert [v.sha256 for v in retrained.store.stale()] == [SHA_A]
    retrained.record_verdict(SHA_A, "benign", content_hashes(ORIGINAL))   # re-analysed
    assert retrained.store.stale() == []
    [entry] = retrained.store.history(SHA_A)
    assert (entry["action"], entry["old_verdict"], entry["new_verdict"]) == ("recheck", "malicious", "benign")


def test_analyst_verdicts_are_never_stale(tmp_path):
    db = tmp_path / "v.sqlite3"
    _svc(db, PROV_OLD).override(SHA_A, "malicious", "asha", "confirmed")
    assert _svc(db, PROV_NEW).lookup(exact_hash.hash_bytes(ORIGINAL)).hit


# --- API -------------------------------------------------------------------
@pytest.fixture
def api(monkeypatch):
    from backend.api.main import app
    from backend.api.routes import verdicts as route
    from config.settings import get_settings

    svc = _svc()
    monkeypatch.setattr(route, "_lookup", svc)
    monkeypatch.setattr(get_settings(), "analyst_token", "t0ken")
    return TestClient(app), svc


def test_api_requires_token(api, monkeypatch):
    client, _ = api
    body = {"verdict": "benign", "analyst": "asha", "reason": "x"}
    assert client.post(f"/v1/verdicts/{SHA_A}/override", json=body).status_code == 403
    from config.settings import get_settings
    monkeypatch.setattr(get_settings(), "analyst_token", "")
    assert client.post(f"/v1/verdicts/{SHA_A}/override", json=body,
                       headers={"X-Analyst-Token": ""}).status_code == 503


def test_api_override_clear_history(api):
    client, svc = api
    svc.record_verdict(SHA_A, "malicious", content_hashes(ORIGINAL))
    h = {"X-Analyst-Token": "t0ken"}
    r = client.post(f"/v1/verdicts/{SHA_A}/override", headers=h,
                    json={"verdict": "benign", "analyst": "asha", "reason": "vendor app"})
    assert r.status_code == 200 and r.json()["stored"]["verdict"] == "benign"
    r = client.post(f"/v1/verdicts/{SHA_A}/clear", headers=h, json={"analyst": "asha", "reason": "undo"})
    assert [e["action"] for e in r.json()["history"]] == ["override", "clear"]
    assert client.get("/v1/verdicts/not-a-hash", headers=h).status_code == 422
    assert client.get("/v1/verdicts/stale", headers=h).json()["count"] == 0


# --- pipeline ----------------------------------------------------------------
def test_pipeline_records_provenance_and_rechecks_stale(tmp_path, monkeypatch):
    import asyncio

    from backend.common.storage import ReportStore
    from backend.orchestration import pipeline
    from schemas.report import InputType
    from tests.test_category import _apk

    # benign.dex: suspicious.dex now trips R002 (accessibility + overlay with no category).
    data = _apk(tmp_path, "benign").read_bytes()
    sha = exact_hash.hash_bytes(data).sha256
    store = ReportStore(tmp_path / "reports")
    monkeypatch.setattr(pipeline, "report_store", lambda: store)
    db = tmp_path / "v.sqlite3"
    _svc(db, PROV_OLD).record_verdict(sha, "benign")              # judged by an old model
    svc = _svc(db, PROV_NEW)
    monkeypatch.setattr(pipeline, "_lookup", svc)

    report = asyncio.run(pipeline.analyze(InputType.apk, data=data, filename="x.apk")).report
    assert report.verdict.stale_previous_verdict == "benign"      # re-analysed, not reused
    assert report.verdict.provenance["source"] == "static"
    assert report.verdict.provenance["fingerprint"] == provenance.current()["fingerprint"]
    # Its manifest is unreadable -> "unknown", which is not remembered (re-analysed next time).
    assert report.verdict.label.value == "unknown"
    assert svc.store.get(sha).verdict == "benign" and svc.store.stale()


def test_cli(tmp_path, capsys):
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "verdicts_cli", Path(__file__).resolve().parents[1] / "scripts" / "verdicts.py")
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    db = str(tmp_path / "v.sqlite3")
    assert cli.main(["--db", db, "override", SHA_A, "malicious", "--analyst", "asha", "--reason", "ok"]) == 0
    assert '"action": "override"' in capsys.readouterr().out
    assert cli.main(["--db", db, "stale"]) == 0
    assert "0 stale" in capsys.readouterr().out
    assert cli.main(["--db", db, "clear", "f" * 64, "--analyst", "a", "--reason", "r"]) == 1
