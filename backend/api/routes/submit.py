"""/v1/submit — primary analysis endpoint (APK upload or URL)."""
from __future__ import annotations

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from backend.api.dependencies import resolve_action
from backend.orchestration import analyze
from schemas.report import InputType, Report, Touchpoint

router = APIRouter()


class SubmitResponse(BaseModel):
    """Report plus the resolved graduated-response action for the caller."""
    action: str            # allow | warn | block
    sandbox_job_id: str | None = None
    report: Report


@router.post("/submit/url", response_model=SubmitResponse)
async def submit_url(url: str = Form(...),
                     touchpoint: Touchpoint = Form(Touchpoint.api),
                     force_dynamic: bool = Form(False)) -> SubmitResponse:
    result = await analyze(InputType.url, url=url, touchpoint=touchpoint,
                           force_dynamic=force_dynamic)
    action = resolve_action(result.report.risk.score, touchpoint.value)
    return SubmitResponse(action=action, sandbox_job_id=result.sandbox_job_id,
                          report=result.report)


@router.post("/submit/apk", response_model=SubmitResponse)
async def submit_apk(file: UploadFile = File(...),
                     touchpoint: Touchpoint = Form(Touchpoint.api),
                     force_dynamic: bool = Form(False)) -> SubmitResponse:
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="empty upload")
    result = await analyze(
        InputType.apk, data=data, filename=file.filename, touchpoint=touchpoint,
        force_dynamic=force_dynamic,
    )
    action = resolve_action(result.report.risk.score, touchpoint.value)
    return SubmitResponse(action=action, sandbox_job_id=result.sandbox_job_id,
                          report=result.report)
