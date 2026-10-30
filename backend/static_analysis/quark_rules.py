"""Optional Quark-Engine behaviour rules (`pip install -e ".[quark]"`).

Quark (https://github.com/quark-engine/quark-engine, GPL-3.0) checks each rule
in five steps: permission, first API, both APIs, call sequence, and data flow
between the calls (same register). Confidence = 20% per step passed. We report
behaviours at >= `quark_min_confidence` (default 80%: the APIs are called in
sequence or with data flowing between them), as evidence for the analyst.

Licensing: Quark is GPL-3.0 and used strictly as an external, optional
dependency (imported at runtime, never copied in). The rules
(https://github.com/quark-engine/quark-rules) are not vendored; fetch them at
the pinned commit (docs/QUARK.md) and set QUARK_RULES_DIR.

Scored only at stage 4-5: a fraud-relevant behaviour (SMS, accessibility, overlay)
at >= 80% confidence is rule R005, one of the three hard overrides
(scoring/rules_engine.py). Lower-confidence behaviours are report evidence only.

CURRENT STATE / PLANNED:
- Current: optional; without QUARK_RULES_DIR, no stage 4-5 evidence exists and
  nothing behavioural blocks by itself. The keyword list deciding which Quark
  rules are fraud-relevant hasn't been checked against the whole rule set.
- Planned: run Quark on the APK test set, measure each rule's benign firing rate
  (ml/eval/benign_firing_rates.py), keep only rules under 1%, and add our own
  data-flow check (SMS read -> network) so stage 5 doesn't depend on Quark alone.

Note: importing Quark creates ~/.quark-engine/ in the user's home directory.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class QuarkBehaviour:
    rule: str            # e.g. "00109.json"
    crime: str           # rule description
    confidence: int      # 0..100
    score: float
    labels: list[str] = field(default_factory=list)


@dataclass
class QuarkReport:
    status: str = "disabled"     # observed | disabled | failed
    reason: str = ""
    threat_level: Optional[str] = None
    total_score: Optional[int] = None
    behaviours: list[QuarkBehaviour] = field(default_factory=list)


def _settings():
    from config.settings import get_settings

    return get_settings()


def _rules_dir() -> Optional[Path]:
    raw = _settings().quark_rules_dir
    return Path(raw) if raw else None


def from_json_report(report: dict, min_confidence: int) -> QuarkReport:
    """Quark's JSON report -> QuarkReport, keeping behaviours >= min_confidence."""
    behaviours = []
    for crime in report.get("crimes", []):
        conf = int(str(crime.get("confidence", "0")).rstrip("%") or 0)
        if conf >= min_confidence:
            behaviours.append(QuarkBehaviour(
                rule=crime.get("rule", ""),
                crime=crime.get("crime", ""),
                confidence=conf,
                score=float(crime.get("score", 0.0)),
                labels=list(crime.get("label", [])),
            ))
    behaviours.sort(key=lambda b: (-b.confidence, -b.score, b.rule))
    return QuarkReport(
        status="observed",
        reason=f"Quark-Engine behaviour rules (confidence >= {min_confidence}%).",
        threat_level=report.get("threat_level"),
        total_score=report.get("total_score"),
        behaviours=behaviours,
    )


def analyze(path: str | Path) -> QuarkReport:
    """Run all Quark rules on an APK (or DEX). Never raises."""
    rules = _rules_dir()
    if rules is None:
        return QuarkReport("disabled", "Quark not configured (set QUARK_RULES_DIR; see docs/QUARK.md).")
    if not rules.is_dir():
        return QuarkReport("disabled", f"QUARK_RULES_DIR does not exist: {rules}")
    try:
        from quark.report import Report  # optional GPL dependency, imported at runtime only
    except ImportError:
        return QuarkReport("disabled", "quark-engine is not installed (pip install -e \".[quark]\").")
    try:
        report = Report()
        report.analysis(str(path), str(rules))
        return from_json_report(report.get_report("json"), _settings().quark_min_confidence)
    except Exception as e:  # a crash in an optional analyser must not fail the pipeline
        logger.warning("Quark analysis failed: %r", e)
        return QuarkReport("failed", f"Quark analysis failed: {type(e).__name__}")
