from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from backend.api.main import app
from backend.api.routes import hash_lookup as hash_route
from backend.api.routes import reports as reports_route
from backend.api.routes import submit as submit_route
from backend.api.routes import webhook as webhook_route
from backend.common.storage import ReportStore
from backend.hashing.lookup import LookupResult
from backend.orchestration import pipeline
from backend.orchestration.job_queue import Job, JobStatus
from backend.scoring.risk_score import RiskResult
from schemas.report import (
    DynamicFindings,
    Evidence,
    Hashes,
    InputInfo,
    InputType,
    NetworkEvent,
    Report,
    ReportStatus,
    Stage,
    Touchpoint,
    Verdict,
)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def report() -> Report:
    return Report(
        report_id="report-api-1",
        status=ReportStatus.complete,
        input=InputInfo(input_type=InputType.apk, source_touchpoint=Touchpoint.api),
        hashes=Hashes(sha256="a" * 64),
        verdict=Verdict(
            label="suspicious",
            confidence=0.8,
            decision_path=[Stage.static_analysis],
        ),
        risk={"score": 0.5, "severity": "medium"},
    )


def test_upload_apk(client: TestClient, monkeypatch: pytest.MonkeyPatch, report: Report):
    async def fake_analyze(*args, **kwargs):
        return SimpleNamespace(report=report, sandbox_job_id=None)

    monkeypatch.setattr(submit_route, "analyze", fake_analyze)

    response = client.post(
        "/v1/submit/apk",
        files={"file": ("sample.apk", b"fake-apk", "application/vnd.android.package-archive")},
        data={"touchpoint": "api"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["report"]["report_id"] == report.report_id
    assert body["sandbox_job_id"] is None


def test_submit_url(client: TestClient, monkeypatch: pytest.MonkeyPatch, report: Report):
    async def fake_analyze(*args, **kwargs):
        assert kwargs["url"] == "https://example.test/app.apk"
        return SimpleNamespace(report=report, sandbox_job_id=None)

    monkeypatch.setattr(submit_route, "analyze", fake_analyze)

    response = client.post(
        "/v1/submit/url",
        data={"url": "https://example.test/app.apk", "touchpoint": "api"},
    )

    assert response.status_code == 200
    assert response.json()["report"]["report_id"] == report.report_id


@dataclass
class FakeLookup:
    result: object

    def lookup(self, exact, fuzzy):
        return self.result


def test_hash_lookup_hit_and_miss(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    hit = LookupResult(hit=True, verdict="malicious", matched_by="exact", cluster_id=None)
    monkeypatch.setattr(hash_route, "_lookup", FakeLookup(hit))
    response = client.post("/v1/hash/lookup", json={"sha256": "b" * 64})
    assert response.status_code == 200
    assert response.json() == {
        "known": True,
        "verdict": "malicious",
        "action": "block",
        "matched_by": "exact",
        "cluster_id": None,
        "fuzzy_status": "available",
        "verdict_source": None,
        "stale": False,
    }

    miss = LookupResult(hit=False, verdict=None, matched_by=None, cluster_id="fam-test",
                        fuzzy_status="unavailable")
    monkeypatch.setattr(hash_route, "_lookup", FakeLookup(miss))
    response = client.post("/v1/hash/lookup", json={"sha256": "c" * 64})
    assert response.status_code == 200
    assert response.json() == {
        "known": False,
        "verdict": None,
        "action": "allow",
        "matched_by": None,
        "cluster_id": "fam-test",
        "fuzzy_status": "unavailable",
        "verdict_source": None,
        "stale": False,
    }

    stale = LookupResult(hit=False, stale_verdict="malicious")
    monkeypatch.setattr(hash_route, "_lookup", FakeLookup(stale))
    body = client.post("/v1/hash/lookup", json={"sha256": "d" * 64}).json()
    # Judged bad by an older model: warn until re-analysed, never silently allow.
    assert (body["known"], body["stale"], body["action"]) == (False, True, "warn")


def test_retrieve_report_and_mitre_heatmap(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    report: Report,
):
    store = ReportStore()
    store.save(report)
    monkeypatch.setattr(reports_route, "report_store", lambda: store)

    response = client.get(f"/v1/reports/{report.report_id}")
    assert response.status_code == 200
    assert response.json()["report_id"] == report.report_id

    response = client.get(f"/v1/reports/{report.report_id}/mitre-heatmap")
    assert response.status_code == 200
    assert response.json() == []


def test_report_summaries_for_the_portal_inbox(client, monkeypatch, tmp_path, report):
    from datetime import datetime, timedelta
    store = ReportStore(tmp_path)
    old = report.model_copy(update={"report_id": "old", "created_at": datetime(2026, 1, 1)})
    new = report.model_copy(update={"report_id": "new", "created_at": datetime(2026, 1, 1) + timedelta(days=1)})
    store.save(old)
    store.save(new)
    monkeypatch.setattr(reports_route, "report_store", lambda: store)
    rows = client.get("/v1/reports/summaries").json()
    assert [r["report_id"] for r in rows] == ["new", "old"]          # newest first
    assert set(rows[0]) >= {"name", "verdict", "score", "severity", "status", "scoring_mode"}


class FakeQueue:
    def __init__(self, job: Job):
        self.job = job

    def status(self, job_id: str):
        return self.job if job_id == self.job.job_id else None


def test_retrieve_job_status(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    job = Job(
        job_id="job-api-1",
        status=JobStatus.done,
        result={"report_id": "report-api-1"},
        meta={"report_id": "report-api-1"},
    )
    monkeypatch.setattr(reports_route, "job_queue", lambda: FakeQueue(job))

    response = client.get("/v1/jobs/job-api-1")
    assert response.status_code == 200
    assert response.json() == {
        "job_id": "job-api-1",
        "status": "done",
        "report_id": "report-api-1",
        "result": {"report_id": "report-api-1"},
        "error": None,
    }


def test_device_health_scoring(client: TestClient):
    response = client.post(
        "/v1/signals/device-health",
        json={
            "package_name": "com.example.bank",
            "unknown_sources_enabled": True,
            "is_rooted_hint": True,
            "developer_mode": True,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["device_risk_score"] == pytest.approx(0.40)
    assert body["action"] == "warn"
    assert "Root indicators present" in body["reasons"]


def test_whatsapp_url_message(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, report: Report
):
    async def fake_analyze(*args, **kwargs):
        assert kwargs["touchpoint"] == Touchpoint.whatsapp_bot
        return SimpleNamespace(report=report, sandbox_job_id=None)

    monkeypatch.setattr(webhook_route, "analyze", fake_analyze)

    response = client.post(
        "/v1/webhook/message",
        json={"sender": "user-1", "text": "Please check https://example.test/a.apk"},
    )

    assert response.status_code == 200
    assert response.json()["verdict"] == "suspicious"
    assert response.json()["action"] == "warn"


def test_sandbox_completion_updates_report(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    report: Report,
):
    store = ReportStore()
    report.status = ReportStatus.processing
    store.save(report)
    monkeypatch.setattr(pipeline, "report_store", lambda: store)

    updated = report.model_copy(
        update={
            "status": ReportStatus.complete,
            "dynamic_findings": DynamicFindings(
                executed=True,
                sandbox_run_id="sandbox-1",
                runtime_behaviors=["sms_interception"],
                network=[NetworkEvent(kind="dns", indicator="c2.example")],
            ),
            "evidence": [
                Evidence(
                    evidence_id="ev-dynamic-1",
                    source="dynamic",
                    summary="Runtime behavior observed: sms_interception.",
                )
            ],
        }
    )

    monkeypatch.setattr(
        pipeline,
        "score_static",
        lambda *args, **kwargs: RiskResult(
            score=0.75,
            severity="high",
            components={"runtime_behaviors": 0.05},
            verdict_label="malicious",
        ),
    )
    monkeypatch.setattr(
        pipeline,
        "consolidate",
        lambda *args, **kwargs: SimpleNamespace(iocs=[]),
    )
    monkeypatch.setattr(pipeline, "build_report", lambda **kwargs: updated)

    bundle = SimpleNamespace(
        run_id="sandbox-1",
        dynamic=SimpleNamespace(
            behavior_report=SimpleNamespace(
                runtime_behaviors=["sms_interception"], overlay_attempts=0
            ),
            network_indicators=[],
        ),
    )
    pipeline._finalize_sandbox_report(
        report.report_id, SimpleNamespace(iocs=object()), bundle
    )

    monkeypatch.setattr(reports_route, "report_store", lambda: store)
    response = client.get(f"/v1/reports/{report.report_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "complete"
    assert body["dynamic_findings"]["sandbox_run_id"] == "sandbox-1"
    assert body["evidence"][0]["source"] == "dynamic"
