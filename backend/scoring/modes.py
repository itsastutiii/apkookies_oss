"""Scoring modes: which engine turns static evidence into the base score.

  rules      Transparent: static analysis + knowledge graph + rules, NO ML model.
             The base score is a sum of hand-set, published evidence weights
             (risk_score._transparent_evidence); every step is in risk.breakdown.
  model      The shipped model (KG -> R-GCN -> Bayesian -> XGBoost) + rules.
             EXPERIMENTAL: trained on a permission-flag dataset, not on APKs
             analysed by this pipeline (see ARCHITECTURE.md, model evaluation).
  retrained  The same stack with models retrained on AndroZoo features,
             loaded from ml/models/retrained/. Refuses to run until they exist.

Rules (R001-R005, graded by evidence stage) apply on top in every mode.

CURRENT STATE / PLANNED: "retrained" has no models yet; they come
from AndroZoo features (ml/training/train_scoring_models.py header, ARCHITECTURE.md).

The mode is `scoring_mode` in config/thresholds.yaml (default: model), and can be
overridden per process with APKOOKIES_SCORING_MODE. It is part of every verdict's
provenance, so switching it makes remembered verdicts stale and they get re-checked.
"""
from __future__ import annotations

import os
from pathlib import Path

from config import thresholds

MODES = ("rules", "model", "retrained")
DEFAULT_MODE = "model"
ENV_VAR = "APKOOKIES_SCORING_MODE"

_MODELS = Path(__file__).resolve().parents[2] / "ml" / "models"
MODEL_FILENAMES = ("rgcn.pt", "bayesian.joblib", "xgboost.json", "xgboost.meta.json")

LABELS = {
    "rules": "rules (transparent, no ML)",
    "model": "model (experimental)",
    "retrained": "retrained model",
}


class ScoringModeError(RuntimeError):
    pass


def validate(mode: str) -> str:
    mode = (mode or "").strip().lower()
    if mode not in MODES:
        raise ScoringModeError(f"unknown scoring mode {mode!r}; use one of {', '.join(MODES)}")
    return mode


def current_mode() -> str:
    return validate(os.environ.get(ENV_VAR) or thresholds().get("scoring_mode") or DEFAULT_MODE)


def model_dir(mode: str) -> Path | None:
    """Where this mode's model files live (None: the mode uses no model)."""
    return {"rules": None, "model": _MODELS, "retrained": _MODELS / "retrained"}[validate(mode)]


def model_files(mode: str) -> dict[str, Path]:
    d = model_dir(mode)
    return {} if d is None else {name: d / name for name in MODEL_FILENAMES}


def require_models(mode: str) -> None:
    """The retrained mode must never silently fall back to cold-start weights."""
    if mode == "retrained":
        missing = [n for n, p in model_files(mode).items() if not p.exists()]
        if missing:
            raise ScoringModeError(
                f"scoring_mode is 'retrained' but ml/models/retrained/ lacks {', '.join(missing)}. "
                "Train them (ml/training/) or switch scoring_mode back to 'model' or 'rules'.")
