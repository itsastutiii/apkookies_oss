"""Report aggregation — assemble the shared Report from all pipeline stages.

Single place that maps internal dataclasses onto the schemas.Report contract,
builds the canonical `evidence` list (which GenAI must cite), computes MITRE
mappings, severity/human-review flags, and recommendations.
"""
from __future__ import annotations

from datetime import datetime
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from backend.reporting import genai, mitre_mapping, recommendations
from backend.scoring.knowledge_graph import default_graph
from backend.scoring.risk_score import RiskResult
from backend.static_analysis import StaticBundle
from backend.threat_intel.ioc import IntelResult
from config import thresholds
from schemas.report import (
    AntiAnalysis,
    ApiUsage,
    BankAllowlistCheck,
    Behaviour,
    Certificate,
    Evidence,
    Hashes,
    IOC,
    InputInfo,
    MitreTechnique,
    Report,
    ReportStatus,
    Severity,
    Risk,
    RuleHit,
    ScoreStep,
    Signing,
    StaticFindings,
    ThreatIntel,
    Verdict,
    VerdictLabel,
)


def _evidence_id(prefix: str, n: int) -> str:
    return f"ev-{prefix}-{n}"


def _jsonable(value):
    """Convert internal dataclasses and enums into report-safe JSON values."""
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _static_bundle_snapshot(static: StaticBundle) -> dict:
    return _jsonable(static)


def _dynamic_bundle_snapshot(bundle) -> dict | None:
    if bundle is None:
        return None
    return _jsonable({
        "run_id": bundle.run_id,
        "dynamic": bundle.dynamic,
        "artifacts": bundle.artifacts,
        "session": bundle.session,
    })


def build_report(
    *,
    input_info: InputInfo,
    hashes: Hashes,
    static: StaticBundle,
    risk: RiskResult,
    intel: IntelResult,
    decision_path: list,
    dynamic=None,
    dynamic_bundle=None,
    report_id: Optional[str] = None,
    status: ReportStatus = ReportStatus.complete,
    sandbox_job_id: Optional[str] = None,
    created_at: Optional[datetime] = None,
    completed_at: Optional[datetime] = None,
) -> Report:
    evidence: list[Evidence] = []

    def add_ev(source: str, summary: str, raw_ref: str | None = None) -> str:
        eid = _evidence_id(source, len(evidence) + 1)
        evidence.append(Evidence(evidence_id=eid, source=source, summary=summary, raw_ref=raw_ref))
        return eid

    # --- static findings + evidence ---
    manifest = static.structural.manifest
    caps = risk.capabilities
    if manifest.permissions:
        add_ev("static", f"Requests {len(manifest.permissions)} permissions: "
                          f"{', '.join(manifest.permissions[:8])}"
                          + ("…" if len(manifest.permissions) > 8 else ""))
    sig = static.structural.signing
    if sig.allowlist.status in ("genuine", "impersonation"):
        add_ev("static", sig.allowlist.detail)
    if sig.debug_signed:
        add_ev("static", "Signed with the Android SDK debug certificate (release apps never are).")
    heatmap = mitre_mapping.HeatmapBuilder()
    cap_techniques = {
        m.capability: m.mitre_techniques
        for m in default_graph().derive_capabilities(manifest.permissions, risk.category)
    }
    for cap in caps:
        eid = add_ev("knowledge_graph", f"Derived capability '{cap}' from permission set.")
        for tid in cap_techniques.get(cap, []):
            heatmap.add(tid, eid, "permission")
    # Only observations flagged suspicious for the app's category, or behind a rule
    # that fired, become evidence and MITRE entries: e.g. sending SMS is expected from a
    # messaging app, so listing every API call as an "attack technique" would flood the
    # heatmap with normal behaviour. A rule hit is a judgement on those exact calls (R002
    # fires on accessibility + overlay with no category at all), so its calls count.
    implicated = set()
    for hit in risk.rules_triggered:
        implicated |= mitre_mapping.RULE_API_CATEGORIES.get(hit.rule_id, set())
    for obs in static.api_usage.observations:
        if obs.suspicious or obs.category.value in implicated:
            why = "Suspicious" if obs.suspicious else "Rule-implicated"
            eid = add_ev("static", f"{why} {obs.category.value} API usage: {obs.context}.")
            for tid in mitre_mapping.API_RULE_TECHNIQUES.get(obs.marker, []):
                heatmap.add(tid, eid, "api_call")
    for f in static.anti_analysis.findings:
        where = f" in {', '.join(f.locations[:3])}" if f.locations else ""
        weak = " (also common in legitimate apps)" if f.common_in_benign else ""
        eid = add_ev("static",
                     f"Anti-analysis technique '{f.technique}' (MITRE {f.mitre_id}){where}{weak}.")
        heatmap.add(f.mitre_id, eid, "api_call")
    for b in static.quark.behaviours:
        add_ev("static", f"Quark rule {b.rule} ({b.confidence}% confidence): {b.crime}.")
    for hit in risk.rules_triggered:
        add_ev("static", f"Rule {hit.rule_id}: {hit.description}")

    dynamic_behavior_evidence: dict[str, str] = {}
    if dynamic is not None:
        for behavior in dynamic.runtime_behaviors:
            dynamic_behavior_evidence[behavior] = add_ev(
                "dynamic", f"Runtime behavior observed: {behavior}.",
                dynamic.sandbox_run_id,
            )
        for event in dynamic.network:
            flags = []
            if event.is_c2:
                flags.append("C2")
            if event.is_exfil:
                flags.append("exfiltration")
            suffix = f" ({', '.join(flags)})" if flags else ""
            add_ev("dynamic", f"Observed {event.kind} network indicator {event.indicator}{suffix}.",
                   dynamic.sandbox_run_id)

    # --- MITRE heatmap: permission (KG) < api_call (static code) < runtime (sandbox) ---
    if dynamic is not None:
        for behavior in dynamic.runtime_behaviors:
            technique_id = mitre_mapping.RUNTIME_BEHAVIOR_TECHNIQUES.get(behavior)
            if technique_id:
                heatmap.add(technique_id, dynamic_behavior_evidence[behavior], "runtime")
    mitre = heatmap.build()

    # --- threat intel ---
    intel_iocs = [
        IOC(type=i.type, value=i.value, telegram_c2_live=i.telegram_c2_live,
            enrichment=i.enrichment)
        for i in intel.iocs
    ]
    for i in intel.iocs[:20]:
        if i.type == "ip_like":
            add_ev("threat_intel", f"IP-like string, unconfirmed (no network context; may be a "
                                   f"version number): {i.value}")
        else:
            add_ev("threat_intel", f"IOC ({i.type}, {i.source}): {i.value}")

    severity = risk.severity
    human_review = risk.score >= thresholds()["human_review_required_at_or_above"]

    report = Report(
        report_id=report_id or __import__("uuid").uuid4().hex,
        status=status,
        sandbox_job_id=sandbox_job_id,
        created_at=created_at or datetime.utcnow(),
        completed_at=completed_at,
        human_review_required=human_review,
        input=input_info,
        hashes=hashes,
        verdict=Verdict(
            label=VerdictLabel(risk.verdict_label),
            confidence=min(risk.score + 0.1, 1.0),
            decision_path=decision_path,
        ),
        risk=Risk(
            score=risk.score,
            scoring_mode=risk.scoring_mode,
            severity=Severity(severity),
            components=risk.components,
            breakdown=[ScoreStep(**vars(s)) for s in risk.breakdown],
            rules_triggered=[
                RuleHit(rule_id=h.rule_id, description=h.description,
                        hard_override=h.hard_override, min_score=h.min_score or None,
                        weight=h.weight or None, stage=h.stage)
                for h in risk.rules_triggered
            ],
        ),
        static_bundle=_static_bundle_snapshot(static),
        dynamic_bundle=_dynamic_bundle_snapshot(dynamic_bundle),
        static_findings=StaticFindings(
            permissions=manifest.permissions,
            capabilities=caps,
            signing=Signing(
                schemes=static.structural.signing.schemes,
                debug_signed=static.structural.signing.debug_signed,
                app_name=static.structural.signing.app_name,
                certificates=[Certificate(**vars(c)) for c in static.structural.signing.certificates],
                bank_allowlist=BankAllowlistCheck(**vars(static.structural.signing.allowlist)),
            ),
            api_usage=[
                ApiUsage(category=o.category.value, context=o.context, suspicious=o.suspicious,
                         rule_id=o.marker, evidence=o.evidence, locations=o.locations)
                for o in static.api_usage.observations
            ],
            obfuscation=static.code_intel.obfuscation,
            behaviours=[
                Behaviour(rule=b.rule, description=b.crime, confidence=b.confidence,
                          score=b.score, labels=b.labels)
                for b in static.quark.behaviours
            ],
            anti_analysis=[
                AntiAnalysis(technique=f.technique, mitre_id=f.mitre_id,
                             detected_where=f.detected_where, markers=f.markers_hit,
                             locations=f.locations, evidence=f.evidence,
                             common_in_benign=f.common_in_benign)
                for f in static.anti_analysis.findings
            ],
        ),
        dynamic_findings=dynamic,
        threat_intel=ThreatIntel(iocs=intel_iocs),
        mitre_attack=[
            MitreTechnique(technique_id=m.technique_id, technique_name=m.technique_name,
                           tactic=m.tactic, evidence_refs=m.evidence_refs,
                           evidence_strength=m.evidence_strength,
                           attack_version=m.attack_version)
            for m in mitre
        ],
        evidence=evidence,
    )

    # GenAI explanation (RAG-grounded) + recommendations, computed last.
    report.explanation = genai.explain(report)
    report.recommendations = recommendations.build(report)
    return report
