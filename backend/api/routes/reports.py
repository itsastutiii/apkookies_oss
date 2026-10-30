"""/v1/reports — SOC analyst portal read API.

Serves stored reports for the dashboard: list submissions, fetch a full report
(static/dynamic findings, MITRE heatmap, risk breakdown, GenAI summary),
sandbox-job status, STIX export, and the Telegram-token liveness probe.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.common.storage import report_store
from backend.orchestration.job_queue import job_queue
from backend.threat_intel.stix_export import to_stix_bundle
from schemas.report import Report

router = APIRouter()


@router.get("/reports")
async def list_reports() -> list[str]:
    return report_store().list_ids()


class ReportSummary(BaseModel):
    """One inbox row for the SOC portal (the full report is fetched on click)."""
    report_id: str
    created_at: datetime
    status: str
    input_type: str
    name: str                      # filename or URL
    verdict: str
    score: float
    severity: str
    scoring_mode: Optional[str] = None


@router.get("/reports/summaries", response_model=list[ReportSummary])
async def list_report_summaries(limit: int = 200) -> list[ReportSummary]:
    """Newest first. Declared before /reports/{report_id} so "summaries" isn't taken as an id."""
    store = report_store()
    rows = []
    for report_id in store.list_ids():
        r = store.get(report_id)
        if r is None:
            continue
        rows.append(ReportSummary(
            report_id=r.report_id, created_at=r.created_at, status=r.status.value,
            input_type=r.input.input_type.value,
            name=r.input.filename or r.input.url or r.input.package_name or r.report_id[:12],
            verdict=r.verdict.label.value, score=r.risk.score, severity=r.risk.severity.value,
            scoring_mode=getattr(r.risk, "scoring_mode", None)))
    rows.sort(key=lambda x: x.created_at, reverse=True)
    return rows[:max(1, min(limit, 1000))]


@router.get("/reports/{report_id}", response_model=Report)
async def get_report(report_id: str) -> Report:
    report = report_store().get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="report not found")
    return report


@router.get("/reports/{report_id}/stix")
async def get_report_stix(report_id: str) -> dict:
    report = report_store().get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="report not found")
    return to_stix_bundle(report)


@router.get("/reports/{report_id}/mitre-heatmap")
async def get_mitre_heatmap(report_id: str) -> list:
    report = report_store().get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="report not found")
    return [t.model_dump() for t in report.mitre_attack]


@router.get("/jobs/{job_id}")
async def get_job(job_id: str) -> dict:
    job = job_queue().status(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return {"job_id": job.job_id, "status": job.status.value,
            "report_id": job.report_id,
            "result": job.result, "error": job.error}


@router.post("/reports/{report_id}/telegram-liveness")
async def telegram_liveness(report_id: str) -> dict:
    """Probe extracted Telegram bot tokens for C2 liveness (SOC-analyst opt-in).

    TODO(low-priority/outline): rate-limit + audit-log; only probe on explicit
    analyst action. Wire backend.threat_intel.telegram_check.check_token here.
    """
    report = report_store().get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="report not found")
    tokens = [i.value for i in report.threat_intel.iocs if i.type == "telegram_token"]
    return {"tokens_found": len(tokens),
            "note": "Liveness probing is stubbed; wire telegram_check.check_token."}
