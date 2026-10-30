"""/v1/signals — bank-app SDK device-health signal intake.

The SDK passively collects raw device-health signals on login (sideloading,
accessibility misuse, tampering, Play Integrity verdict) and POSTs them here.
The COMPOSITE score is computed server-side (SDK only blocks/warns). This keeps
scoring logic centralized and updatable without shipping a new app version.

TODO: verify the Play Integrity token server-side against Google's API before
trusting its verdict.
"""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from backend.api.dependencies import resolve_action

router = APIRouter()


class DeviceSignals(BaseModel):
    package_name: str
    play_integrity_token: str | None = None      # TODO: verify server-side
    sideloaded_apps: list[str] = Field(default_factory=list)
    accessibility_services_enabled: list[str] = Field(default_factory=list)
    unknown_sources_enabled: bool = False
    is_rooted_hint: bool = False
    developer_mode: bool = False
    overlay_permission_apps: list[str] = Field(default_factory=list)


class DeviceHealthResponse(BaseModel):
    device_risk_score: float
    action: str                  # allow | warn | block
    reasons: list[str]


def _score_signals(s: DeviceSignals) -> tuple[float, list[str]]:
    """Transparent composite device-health score. TODO: learn weights + integrate
    Play Integrity verdict once token verification is wired."""
    score = 0.0
    reasons: list[str] = []
    if s.unknown_sources_enabled:
        score += 0.15; reasons.append("Unknown sources enabled")
    if s.sideloaded_apps:
        score += min(0.10 * len(s.sideloaded_apps), 0.30)
        reasons.append(f"{len(s.sideloaded_apps)} sideloaded app(s)")
    if s.accessibility_services_enabled:
        score += 0.25; reasons.append("Third-party accessibility service(s) active")
    if s.overlay_permission_apps:
        score += 0.20; reasons.append("Apps with overlay permission present")
    if s.is_rooted_hint:
        score += 0.20; reasons.append("Root indicators present")
    if s.developer_mode:
        score += 0.05; reasons.append("Developer mode on")
    return min(score, 1.0), reasons


@router.post("/signals/device-health", response_model=DeviceHealthResponse)
async def device_health(signals: DeviceSignals) -> DeviceHealthResponse:
    score, reasons = _score_signals(signals)
    action = resolve_action(score, "bank_sdk")
    return DeviceHealthResponse(device_risk_score=score, action=action, reasons=reasons)
