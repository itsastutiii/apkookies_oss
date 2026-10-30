"""Recommendation engine: tie findings to concrete response actions.

Deterministic, auditable mapping from (severity, findings) to recommended
actions (block, credential_reset, ioc_blacklist, sandbox_escalation,
fraud_team_notify). Intentionally NOT ML — responses must be predictable and
policy-driven.
"""
from __future__ import annotations

from schemas.report import Recommendation, RecommendationAction, Report, Severity


def build(report: Report) -> list[Recommendation]:
    recs: list[Recommendation] = []
    sev = report.risk.severity

    if sev in (Severity.high, Severity.critical):
        recs.append(Recommendation(
            action=RecommendationAction.block,
            rationale=f"Risk severity is {sev.value}.",
            priority="high",
        ))
    elif sev == Severity.medium:
        recs.append(Recommendation(
            action=RecommendationAction.warn,
            rationale="Medium risk — warn the user and monitor.",
            priority="medium",
        ))

    # OTP/SMS interception or accessibility takeover -> protect the account.
    caps = set(report.static_findings.capabilities)
    if caps & {"SmsInterception", "AccessibilityAbuse", "OverlayAttack"}:
        recs.append(Recommendation(
            action=RecommendationAction.credential_reset,
            rationale="Credential-theft capability detected (SMS/overlay/accessibility).",
            priority="high",
        ))

    # Any C2/exfil IOC -> blacklist.
    if any(i.telegram_c2_live or (i.enrichment or {}).get("is_c2") for i in report.threat_intel.iocs) \
            or report.threat_intel.iocs:
        recs.append(Recommendation(
            action=RecommendationAction.ioc_blacklist,
            rationale="Blacklist extracted IOCs (C2/exfil endpoints).",
            priority="medium",
        ))

    # Uncertain static verdict -> escalate to sandbox.
    if report.verdict.label.value == "unknown":
        recs.append(Recommendation(
            action=RecommendationAction.sandbox_escalation,
            rationale="Static analysis inconclusive; escalate to dynamic sandbox.",
            priority="medium",
        ))

    if sev == Severity.critical:
        recs.append(Recommendation(
            action=RecommendationAction.fraud_team_notify,
            rationale="Critical-severity sample — notify the fraud team for review.",
            priority="high",
        ))

    return recs
