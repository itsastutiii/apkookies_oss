"""/v1/verdicts — analyst review of remembered verdicts.

An analyst can override a stored verdict for one exact file or clear it (so the
file is re-analysed next time). Every action needs an analyst name and reason
and is appended to an audit log. A "benign" override applies to that exact
SHA-256 only and never spreads to look-alikes (hashing/lookup.py).

These endpoints change what every touchpoint is told about a file, so they are
OFF unless ANALYST_TOKEN is configured, and callers must send it as
X-Analyst-Token. This is a stop-gap: real per-user authentication is planned.
"""
from __future__ import annotations

import hmac
import re
from dataclasses import asdict
from typing import Literal

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from backend.orchestration.pipeline import _lookup
from config.settings import get_settings

router = APIRouter()
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _authorise(token: str | None) -> None:
    expected = get_settings().analyst_token
    if not expected:
        raise HTTPException(status_code=503, detail="analyst actions are disabled (ANALYST_TOKEN not set)")
    if not token or not hmac.compare_digest(token.encode(), expected.encode()):
        raise HTTPException(status_code=403, detail="invalid analyst token")


def _check_sha(sha256: str) -> str:
    sha256 = sha256.lower()
    if not _SHA256.fullmatch(sha256):
        raise HTTPException(status_code=422, detail="sha256 must be 64 hex characters")
    return sha256


class OverrideRequest(BaseModel):
    verdict: Literal["benign", "suspicious", "malicious"]
    analyst: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=2000)


class ClearRequest(BaseModel):
    analyst: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=2000)


def _view(sha256: str) -> dict:
    row = _lookup.store.get(sha256, include_cleared=True)
    current = _lookup.store.current_fingerprint
    return {
        "sha256": sha256,
        "stored": None if row is None else {
            **{k: v for k, v in asdict(row).items() if k not in ("sha256",)},
            "stale": row.is_stale(current),
        },
        "current_fingerprint": current,
        "history": _lookup.store.history(sha256),
    }


@router.get("/verdicts/stale")
async def stale_verdicts(x_analyst_token: str | None = Header(default=None)) -> dict:
    _authorise(x_analyst_token)
    rows = _lookup.store.stale()
    return {"count": len(rows), "current_fingerprint": _lookup.store.current_fingerprint,
            "items": [{"sha256": r.sha256, "verdict": r.verdict, "source": r.source,
                       "fingerprint": r.provenance.get("fingerprint")} for r in rows[:1000]]}


@router.get("/verdicts/{sha256}")
async def get_verdict(sha256: str, x_analyst_token: str | None = Header(default=None)) -> dict:
    _authorise(x_analyst_token)
    return _view(_check_sha(sha256))


@router.post("/verdicts/{sha256}/override")
async def override_verdict(sha256: str, req: OverrideRequest,
                           x_analyst_token: str | None = Header(default=None)) -> dict:
    _authorise(x_analyst_token)
    sha256 = _check_sha(sha256)
    _lookup.override(sha256, req.verdict, req.analyst.strip(), req.reason.strip())
    return _view(sha256)


@router.post("/verdicts/{sha256}/clear")
async def clear_verdict(sha256: str, req: ClearRequest,
                        x_analyst_token: str | None = Header(default=None)) -> dict:
    _authorise(x_analyst_token)
    sha256 = _check_sha(sha256)
    if not _lookup.clear(sha256, req.analyst.strip(), req.reason.strip()):
        raise HTTPException(status_code=404, detail="no stored verdict for this sha256")
    return _view(sha256)
