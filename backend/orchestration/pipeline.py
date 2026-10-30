"""Pipeline orchestrator — the core flow tying every module together.

Implements the architecture-diagram flow with tiered latency:

  INPUT (url|apk)
    -> [URL] resolve redirect chain (UA-spoof + cloaking) -> signature branch
    -> acquire sample bytes -> exact+fuzzy hash
    -> TIER 1: hash lookup (exact / fuzzy-cluster inheritance)  [instant]
         hit  -> build report from inherited verdict -> return
         miss -> continue
    -> TIER 2: static analysis -> context-aware KG/R-GCN/Bayesian/rules scoring
              [synchronous]
    -> if uncertain -> escalate to TIER 3 dynamic sandbox  [async job]
    -> consolidate threat intel -> aggregate report (+ MITRE, GenAI, recs)
    -> persist hashes/IOCs/vectors; wipe raw sample.

The URL/HTML phishing-page analysis branch is stubbed (see analyze_url TODO).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import uuid
import shutil
import tempfile
import os
from pathlib import Path
from typing import Optional

from backend.common import provenance
from backend.common.storage import report_store
from backend.hashing import exact_hash, fuzzy_hash
from backend.hashing.content_hash import content_hashes
from backend.hashing.lookup import HashLookupService
from backend.hashing.verdict_store import VerdictStore
from backend.ingestion import acquisition
from backend.ingestion.file_signature import ContentKind
from backend.reporting.aggregator import build_report
from backend.scoring.risk_score import score_static
from backend.static_analysis import run as run_static
from backend.threat_intel.cert_reuse import CertReuseStore
from backend.threat_intel.ioc import consolidate
from config.settings import get_settings
from schemas.report import (
    Hashes,
    InputInfo,
    InputType,
    Report,
    DynamicFindings,
    NetworkEvent,
    ReportStatus,
    ScoreStep,
    Stage,
    Touchpoint,
    Verdict,
    VerdictLabel,
)

# Verdicts persist across restarts (SQLite); the variant indexes and certificate
# reuse are rebuilt from it at start-up.
_lookup = HashLookupService(store=VerdictStore(get_settings().verdict_db_path))
_cert_reuse = CertReuseStore()
for _row in _lookup.store.active():
    _cert_reuse.record(_row.fingerprints, _row.sha256, _row.verdict)


@dataclass
class SubmissionResult:
    report: Report
    sandbox_job_id: Optional[str] = None


async def analyze(input_type: InputType, *, data: bytes | None = None,
                  url: str | None = None,
                  touchpoint: Touchpoint = Touchpoint.api,
                  filename: str | None = None,
                  force_dynamic: bool = False) -> SubmissionResult:
    """Entry point used by every touchpoint. Returns a Report (+ optional async job)."""
    # 1. Ingest.
    if input_type == InputType.url:
        assert url is not None
        sample = await acquisition.from_url(url)
        if sample.kind == ContentKind.html:
            return SubmissionResult(report=_analyze_url_html(url, sample))
        # APK reached via URL -> fall through into the APK pipeline.
    else:
        assert data is not None
        sample = acquisition.from_upload(data, filename=filename)

    input_info = InputInfo(
        input_type=InputType.apk,
        source_touchpoint=touchpoint,
        url=url,
        filename=filename or sample.filename,
    )

    if sample.kind not in (ContentKind.apk,):
        # Not an APK and not HTML -> unsupported for now.
        return SubmissionResult(report=_unsupported_report(input_info, sample.kind))

    # 2. Hash: whole APK (exact + fuzzy) and APK contents (DEX + manifest).
    exact = exact_hash.hash_bytes(sample.data)
    fuzzy = fuzzy_hash.fuzzy_hash_bytes(sample.data)
    content = content_hashes(sample.data)
    hashes = Hashes(
        md5=exact.md5, sha256=exact.sha256, ssdeep=fuzzy.ssdeep, tlsh=fuzzy.tlsh,
        dex_count=content.dex_count, dex_sha256=content.dex_sha256,
        dex_ssdeep=content.dex_ssdeep, dex_tlsh=content.dex_tlsh,
        manifest_sha256=content.manifest_sha256, manifest_ssdeep=content.manifest_ssdeep,
        manifest_tlsh=content.manifest_tlsh,
    )

    # 3. TIER 1: hash lookup / verdict inheritance. Read-only: nothing is stored
    #    until step 7, so a lookup (or a crash mid-analysis) can't plant a verdict.
    #    Only an exact file match may return "benign" (see hashing/lookup.py).
    lk = _lookup.lookup(exact, content)
    hashes.fuzzy_status, hashes.fuzzy_note = lk.fuzzy_status, lk.fuzzy_note
    hashes.cluster_id = lk.cluster_id
    if lk.hit and not force_dynamic:
        hashes.inherited_verdict_from = lk.inherited_from
        report = _fast_path_report(input_info, hashes, lk.verdict or "unknown", lk.matched_by)
        report.verdict.provenance = lk.provenance
        acquisition.wipe(sample)
        report_store().save(report)
        return SubmissionResult(report=report)

    # 4. TIER 2: static analysis + context-aware scoring.
    assert sample.ephemeral_path is not None
    static_bundle = run_static(sample.ephemeral_path)
    risk = score_static(static_bundle)
    report_id = uuid.uuid4().hex

    decision_path = [Stage.hash_exact_lookup, Stage.static_analysis, Stage.static_rule_scoring]
    if any(h.hard_override for h in risk.rules_triggered):
        decision_path.append(Stage.rules_engine_override)

    # 5. Threat intel consolidation.
    intel = consolidate(static_bundle.iocs, network=None)

    # 6. Aggregate and persist the initial report before queueing work.
    sandbox_job_id = None
    dynamic = None
    should_enqueue_sandbox = force_dynamic or risk.needs_dynamic_analysis
    if should_enqueue_sandbox:
        decision_path.append(Stage.dynamic_sandbox)
    decision_path.append(Stage.genai_summary)
    report = build_report(
        input_info=input_info,
        hashes=hashes,
        static=static_bundle,
        risk=risk,
        intel=intel,
        decision_path=decision_path,
        dynamic=dynamic,
        report_id=report_id,
        status=ReportStatus.processing if should_enqueue_sandbox else ReportStatus.complete,
        completed_at=None if should_enqueue_sandbox else datetime.utcnow(),
    )
    report.verdict.provenance = provenance.stamp("static")
    report.verdict.stale_previous_verdict = lk.stale_verdict
    # Certificate reuse is looked up before this sample is recorded, and excludes
    # the sample itself, so a re-submission doesn't count itself as "another sample".
    fingerprints = static_bundle.structural.signing.fingerprints
    others, malicious = _cert_reuse.lookup(fingerprints, exclude_sha256=exact.sha256)
    report.static_findings.signing.cert_reuse.other_samples = others
    report.static_findings.signing.cert_reuse.malicious_samples = malicious
    report_store().save(report)

    if should_enqueue_sandbox:
        try:
            sandbox_job_id = await _enqueue_sandbox(
                report_id, exact.sha256, str(sample.ephemeral_path), static_bundle, content
            )
        except Exception:
            report.status = ReportStatus.failed
            report_store().save(report)
            raise
        report.sandbox_job_id = sandbox_job_id
        report_store().save(report)

    # 7. Persist the static verdict (with provenance) for the fast path; a sandbox
    #    re-score replaces it later. "unknown" (unreadable manifest) is not
    #    remembered, so the sample is analysed again next time. Wipe the raw sample.
    cluster_id = None
    if report.verdict.label.value != "unknown":
        cluster_id = _lookup.record_verdict(exact.sha256, report.verdict.label.value, content,
                                            source="static", fingerprints=fingerprints)
        _cert_reuse.record(fingerprints, exact.sha256, report.verdict.label.value)
    if cluster_id is not None:
        report.hashes.cluster_id = cluster_id
        report_store().save(report)
    acquisition.wipe(sample)

    return SubmissionResult(report=report, sandbox_job_id=sandbox_job_id)


async def _enqueue_sandbox(report_id: str, sha256: str, apk_path: str,
                           static_bundle, content=None) -> str:
    """Enqueue an async sandbox run and return the job id.

    TODO: register a completion hook that re-scores + updates the persisted
    report with the dynamic findings once the job finishes.
    """
    from backend.orchestration.job_queue import job_queue
    from backend.sandbox.run import run_dynamic

    temp_fd, temp_path = tempfile.mkstemp(suffix=".apk")
    os.close(temp_fd)
    temp_apk = Path(temp_path)
    shutil.copy2(apk_path, temp_apk)

    async def _job() -> dict:
        try:
            bundle = run_dynamic(temp_apk, static_bundle=static_bundle, wipe_after=True)
            _finalize_sandbox_report(report_id, static_bundle, bundle, sha256, content)
            return {"report_id": report_id, "run_id": bundle.run_id}
        except Exception:
            report = report_store().get(report_id)
            if report is not None:
                report.status = ReportStatus.failed
                report_store().save(report)
            raise
        finally:
            temp_apk.unlink(missing_ok=True)

    q = job_queue()
    q.start()
    return await q.enqueue(_job, meta={"sha256": sha256, "report_id": report_id})


def _normalize_dynamic(bundle) -> DynamicFindings:
    behavior_report = bundle.dynamic.behavior_report
    if isinstance(behavior_report, dict):
        runtime_behaviors = behavior_report.get("runtime_behaviors", [])
        overlay_attempts = behavior_report.get("overlay_attempts", 0)
    else:
        runtime_behaviors = behavior_report.runtime_behaviors
        overlay_attempts = behavior_report.overlay_attempts
    network = [
        NetworkEvent(
            kind=indicator.kind,
            indicator=indicator.indicator,
            is_c2=indicator.is_c2,
            is_exfil=indicator.is_exfil,
        ) for indicator in bundle.dynamic.network_indicators
    ]
    return DynamicFindings(
        executed=True,
        sandbox_run_id=bundle.run_id,
        runtime_behaviors=runtime_behaviors,
        network=network,
        overlay_attempts=overlay_attempts,
    )


def _finalize_sandbox_report(report_id: str, static_bundle, bundle,
                             sha256: str | None = None, content=None) -> Report:
    report = report_store().get(report_id)
    if report is None:
        raise RuntimeError(f"report {report_id} not found for sandbox completion")

    dynamic_report = bundle.dynamic.behavior_report
    network = bundle.dynamic.network_indicators
    risk = score_static(
        static_bundle,
        dynamic=dynamic_report if not isinstance(dynamic_report, dict) else None,
        network=network,
    )
    decision_path = list(report.verdict.decision_path)
    if Stage.dynamic_sandbox not in decision_path:
        decision_path.append(Stage.dynamic_sandbox)
    updated = build_report(
        input_info=report.input,
        hashes=report.hashes,
        static=static_bundle,
        risk=risk,
        intel=consolidate(static_bundle.iocs, network=network),
        decision_path=decision_path,
        dynamic=_normalize_dynamic(bundle),
        dynamic_bundle=bundle,
        report_id=report.report_id,
        status=ReportStatus.complete,
        sandbox_job_id=report.sandbox_job_id,
        created_at=report.created_at,
        completed_at=datetime.utcnow(),
    )
    updated.verdict.provenance = provenance.stamp("sandbox")
    # The sandbox verdict has more evidence than the static one, so it replaces it
    # in the store (unless an analyst has already decided this sample).
    if sha256 and updated.verdict.label.value != "unknown":
        _lookup.record_verdict(sha256, updated.verdict.label.value, content, source="sandbox",
                               fingerprints=static_bundle.structural.signing.fingerprints)
    report_store().save(updated)
    return updated


# --- helper report builders for non-static-scored paths ------------------
def _fast_path_report(input_info: InputInfo, hashes: Hashes, verdict: str,
                      matched_by: str | None) -> Report:
    stage = {
        "exact": Stage.hash_exact_lookup,
        "dex_exact": Stage.dex_content_match,
    }.get(matched_by or "", Stage.fuzzy_cluster_inheritance)
    from backend.scoring.risk_score import severity_for

    # Hand-set placeholder scores for a remembered verdict (no new analysis ran),
    # chosen to land in block / warn / allow bands. To be calibrated on a labelled test set.
    score = {"malicious": 0.9, "suspicious": 0.5, "benign": 0.1}.get(verdict, 0.5)
    r = Report(report_id=__import__("uuid").uuid4().hex, input=input_info, hashes=hashes)
    r.verdict = Verdict(label=VerdictLabel(verdict), confidence=0.95, decision_path=[stage])
    r.risk.score = score
    # A machine verdict is only reused when its provenance (which includes the scoring
    # mode) matches the running system, so it was made in the current mode.
    from backend.scoring import modes
    r.risk.scoring_mode = modes.current_mode()
    r.risk.breakdown = [ScoreStep(
        step="remembered_verdict", kind="base", delta=score, score_after=score,
        detail=f"No new analysis: '{verdict}' remembered via {matched_by or 'lookup'} match; "
               "placeholder score for that verdict (hand-set).")]
    r.risk.severity = __import__("schemas.report", fromlist=["Severity"]).Severity(
        severity_for(score)
    )
    return r


def _analyze_url_html(url: str, sample) -> Report:
    """Phishing-page (HTML) analysis branch. TODO: implement.

    Should: analyze the resolved HTML for credential-harvesting forms, brand
    impersonation, obfuscated JS, and known phishing-kit fingerprints; extract
    IOCs from the redirect chain; score; report.
    """
    info = InputInfo(input_type=InputType.url, url=url)
    r = Report(report_id=__import__("uuid").uuid4().hex, input=info)
    r.verdict = Verdict(label=VerdictLabel.unknown, confidence=0.0)
    # TODO: real phishing-page classifier + cloaking evidence from sample.url_resolution.
    return r


def _unsupported_report(input_info: InputInfo, kind: ContentKind) -> Report:
    r = Report(report_id=__import__("uuid").uuid4().hex, input=input_info)
    r.verdict = Verdict(label=VerdictLabel.unknown, confidence=0.0)
    return r
