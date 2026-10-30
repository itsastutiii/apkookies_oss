"""What produced a verdict: code, model files, scoring config.

Every stored verdict carries this record so that, after retraining or a scoring
change, verdicts made by the old system can be recognised and re-checked
instead of being reused silently.

`fingerprint()` is what staleness is judged on: the model files, the scoring
config files and SCORING_VERSION. The git commit is recorded for audit but is
deliberately NOT part of it, otherwise every unrelated commit (docs, UI) would
invalidate every remembered verdict.
"""
from __future__ import annotations

import hashlib
import subprocess
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Bump when scoring logic changes in a way that can change verdicts without a
# model or config file changing (e.g. rule semantics, score stacking).
# 2a.2: R003 floor 0.40; R002 split into warn-alone (R002B) / block-with-a-second-signal.
# 2a.3: scoring modes (rules | model | retrained); the mode is part of the fingerprint.
# 2b.1: library code ignored; a11y/overlay manifest gates; IPs need a network context;
#       rules graded by evidence stage (hard overrides only R004/R005); KG boost off.
SCORING_VERSION = "2b.1"

# The shipped model ("model" mode). "retrained" uses the same names under
# ml/models/retrained/; "rules" uses no model file (backend/scoring/modes.py).
MODEL_FILES = ("ml/models/rgcn.pt", "ml/models/bayesian.joblib",
               "ml/models/xgboost.json", "ml/models/xgboost.meta.json")
CONFIG_FILES = ("config/thresholds.yaml", "config/bank_allowlist.yaml", "config/bank_targets.yaml",
                "data/knowledge_graph/seed_ontology.yaml")


def _sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


@lru_cache
def _git_commit() -> str | None:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                             text=True, timeout=10).stdout.strip()
        return out or None
    except (OSError, subprocess.SubprocessError):
        return None


def current(root: Path = ROOT, mode: str | None = None) -> dict:
    """Provenance of verdicts produced by this process right now (in `mode`, default:
    the configured scoring mode). Only the files the mode actually uses are hashed."""
    from backend.scoring import modes    # lazy: keeps this module free of scoring imports

    mode = modes.validate(mode) if mode else modes.current_mode()
    model_rel = {"rules": (), "model": MODEL_FILES,
                 "retrained": tuple(p.replace("ml/models/", "ml/models/retrained/") for p in MODEL_FILES)}
    models = {Path(p).name: _sha256(root / p) for p in model_rel[mode]}
    config = {Path(p).name: _sha256(root / p) for p in CONFIG_FILES}
    record = {
        "scoring_version": SCORING_VERSION,
        "scoring_mode": mode,
        "code_version": _git_commit(),
        "model_files": models,
        "config_files": config,
    }
    record["fingerprint"] = fingerprint(record)
    return record


def fingerprint(record: dict) -> str:
    parts = [record.get("scoring_version") or "", f"mode={record.get('scoring_mode') or 'model'}"]
    for group in ("model_files", "config_files"):
        parts += [f"{k}={v}" for k, v in sorted((record.get(group) or {}).items())]
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:16]


def stamp(source: str, root: Path = ROOT) -> dict:
    """`current()` plus who/what produced the verdict and when."""
    return {**current(root), "source": source,
            "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
