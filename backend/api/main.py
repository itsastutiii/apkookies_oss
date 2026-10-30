"""FastAPI app — the single shared backend API the four touchpoints call.

Design-the-contract-first: every client (bank SDK, WhatsApp bot, browser
extension, SOC portal) speaks to these endpoints and consumes the shared Report
schema. Response policy (allow/warn/block thresholds) is config-driven and
resolved server-side.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.common.logging import configure
from backend.api.routes import genai, hash_lookup, reports, signals, submit, verdicts, webhook

configure()

app = FastAPI(
    title="APKookies API",
    version="0.1.0",
    description="AI-based fraud APK & phishing-URL analysis with explainable risk scoring.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(submit.router, prefix="/v1", tags=["submit"])
app.include_router(hash_lookup.router, prefix="/v1", tags=["hash"])
app.include_router(signals.router, prefix="/v1", tags=["bank_sdk"])
app.include_router(webhook.router, prefix="/v1", tags=["bot"])
app.include_router(reports.router, prefix="/v1", tags=["soc_portal"])
app.include_router(genai.router, prefix="/v1", tags=["genai"])
app.include_router(verdicts.router, prefix="/v1", tags=["analyst"])


@app.get("/health", tags=["ops"])
async def health() -> dict:
    return {"status": "ok", "schema_version": "1.0.0"}
