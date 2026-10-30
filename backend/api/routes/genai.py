"""Gemini-backed analyst utilities."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, field_validator

router = APIRouter()


class ExternalAnalysisRequest(BaseModel):
    analysis_text: str = Field(..., max_length=150_000)

    @field_validator("analysis_text")
    @classmethod
    def require_content(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Analysis text is required.")
        return value


class ExternalAnalysisResponse(BaseModel):
    result: str
    model: str


@router.post("/genai/analyze", response_model=ExternalAnalysisResponse)
async def analyze_external(request: ExternalAnalysisRequest) -> ExternalAnalysisResponse:
    from backend.reporting.genai import analyze_external_outputs

    result, model = analyze_external_outputs(request.analysis_text)
    return ExternalAnalysisResponse(result=result, model=model)