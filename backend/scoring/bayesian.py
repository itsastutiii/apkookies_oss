"""Contextual Bayesian prior.

A trained Bernoulli Naive Bayes model is used when a model artifact exists. It is
an intentionally small Bayesian prior: permission/capability evidence is kept
interpretable and category is an explicit contextual variable. A deterministic
expert prior remains as a safe cold-start fallback.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
try:
    import joblib
    _HAS_JOBLIB = True
except ImportError:
    joblib = None      # type: ignore
    _HAS_JOBLIB = False

_SIGNAL_WEIGHT = {
    "android.permission.SEND_SMS": 0.20,
    "android.permission.READ_SMS": 0.18,
    "android.permission.RECEIVE_SMS": 0.18,
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 0.25,
    "android.permission.SYSTEM_ALERT_WINDOW": 0.22,
    "android.permission.REQUEST_INSTALL_PACKAGES": 0.15,
    "android.permission.RECORD_AUDIO": 0.10,
}
_CATEGORY_MULT = {"banking": 1.4, "wallpaper": 1.3, "game": 1.2, "communication": 0.7, "socialmedia": 0.8}

@dataclass
class BayesianPrior:
    p_high: float
    contributing: dict[str, float]
    model: str = "expert_fallback"

_MODEL = None
_VOCAB: list[str] = []


def load_model(path: str | Path) -> bool:
    if not _HAS_JOBLIB:
        return False
    global _MODEL, _VOCAB
    path = Path(path)
    if not path.exists():
        return False
    payload = joblib.load(path)
    _MODEL = payload["model"]
    _VOCAB = payload["vocab"]
    return True


def set_model(model, vocab: list[str]) -> None:
    global _MODEL, _VOCAB
    _MODEL, _VOCAB = model, vocab


def prior_p_high(permissions: list[str], app_category: str | None) -> BayesianPrior:
    contributing = {p: _SIGNAL_WEIGHT[p] for p in permissions if p in _SIGNAL_WEIGHT}
    # if _MODEL is not None:
    #     row = [1 if p in set(permissions) else 0 for p in _VOCAB]
    #     row.append(float(bool(app_category)))
    #     # category one-hot is handled only by training artifacts that include it;
    #     # for the compact deployed model we use category-specific adjustment below.
    #     p = float(_MODEL.predict_proba([row[:len(_VOCAB)]])[0, 1])
    #     mult = _CATEGORY_MULT.get((app_category or "").lower(), 1.0)
    #     return BayesianPrior(min(max(p * mult, 0.0), 0.99), contributing, "bernoulli_nb")
    if _MODEL is not None:
        row = [1 if p in set(permissions) else 0 for p in _VOCAB]
        p = float(_MODEL.predict_proba([row])[0, 1])
        mult = _CATEGORY_MULT.get((app_category or "").lower(), 1.0)
        # Capped at 1.0 (a real probability bound), NOT an arbitrary 0.99. Training
        # feeds the aggregator XGBoost the RAW, unclipped nb.predict_proba() value;
        # a 0.99 cap here silently diverged from that for confident predictions
        # (~0.999+), and the aggregator has a learned split right at that boundary --
        # flipping some samples' final verdict from malicious to benign.
        return BayesianPrior(max(0.0, min(p * mult, 1.0)), contributing, "bernoulli_nb")
    base = min(sum(contributing.values()), 0.95)
    mult = _CATEGORY_MULT.get((app_category or "").lower(), 1.0)
    return BayesianPrior(max(0.0, min(base * mult, 0.99)), contributing, "expert_fallback")
