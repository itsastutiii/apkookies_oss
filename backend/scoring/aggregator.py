"""XGBoost aggregation for the deployed scoring vector.

The final XGBoost artifact is stored in XGBoost's native JSON format rather than
as a Python pickle. This avoids cross-version estimator deserialization failures.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import json
try:
    import joblib  # type: ignore[import-untyped]
    _HAS_JOBLIB = True
except ImportError:
    joblib = None
    _HAS_JOBLIB = False
from backend.scoring.bayesian import BayesianPrior
from backend.scoring.rgcn import GraphEmbedding

@dataclass
class ScalarFeatures:
    obfuscation_count: int = 0
    anti_analysis_count: int = 0
    suspicious_api_count: int = 0
    self_signed: bool = False
    debug_signed: bool = False
    exported_component_count: int = 0
    sms_api_count: int = 0
    accessibility_api_count: int = 0
    overlay_api_count: int = 0
    network_api_count: int = 0
    telephony_api_count: int = 0
    webview_api_count: int = 0
    crypto_api_count: int = 0
    telegram_token_count: int = 0
    domain_count: int = 0
    ip_count: int = 0
    url_count: int = 0
    permission_count: int = 0
    sensitive_permission_count: int = 0

@dataclass
class AggregatedScore:
    score: float
    components: dict[str, float]
    model: str
    feature_importance: dict[str, float] | None = None

_MODEL = None
_FEATURE_NAMES: list[str] = []


def load_model(path: str | Path) -> bool:
    """Load native XGBoost JSON plus its small metadata sidecar.

    Legacy .joblib artifacts remain readable for backwards compatibility, but
    newly trained repositories should use .json.
    """
    global _MODEL, _FEATURE_NAMES
    path = Path(path)
    if not path.exists():
        return False
    if path.suffix == ".json":
        from xgboost import XGBClassifier
        meta_path = path.with_suffix(".meta.json")
        _MODEL = XGBClassifier()
        _MODEL.load_model(path)
        _FEATURE_NAMES = json.loads(meta_path.read_text(encoding="utf-8"))["feature_names"] if meta_path.exists() else []
        return True
    if not _HAS_JOBLIB:
        return False
    payload = joblib.load(path)
    _MODEL = payload["model"]
    _FEATURE_NAMES = payload["feature_names"]
    return True


def set_model(model, feature_names: list[str]) -> None:
    global _MODEL, _FEATURE_NAMES
    _MODEL, _FEATURE_NAMES = model, feature_names


def aggregate(embedding: GraphEmbedding, prior: BayesianPrior, features: ScalarFeatures) -> AggregatedScore:
    scalars = scalar_vector(features)
    row = [prior.p_high, *embedding.vector, *scalars]
    if _MODEL is not None:
        p = float(_MODEL.predict_proba([row])[0, 1])
        names = _FEATURE_NAMES or ["bayesian_prior"] + [f"rgcn_{i}" for i in range(len(embedding.vector))] + [f"scalar_{i}" for i in range(len(scalars))]
        importance = {n: float(v) for n, v in zip(names, getattr(_MODEL, "feature_importances_", [])) if v > 0}
        return AggregatedScore(
            p,
            {"bayesian_prior": prior.p_high, "rgcn_embedding_signal": min(sum(abs(v) for v in embedding.vector) / max(len(embedding.vector), 1), 1.0)},
            "xgboost",
            importance,
        )
    return _linear_blend(embedding, prior, features)


def scalar_vector(f: ScalarFeatures) -> list[float]:
    return [float(x) for x in (
        f.obfuscation_count, f.anti_analysis_count, f.suspicious_api_count,
        f.self_signed, f.debug_signed, f.exported_component_count,
        f.sms_api_count, f.accessibility_api_count, f.overlay_api_count,
        f.network_api_count, f.telephony_api_count, f.webview_api_count,
        f.crypto_api_count, f.telegram_token_count, f.domain_count, f.ip_count, f.url_count,
        f.permission_count, f.sensitive_permission_count,
    )]


def _norm(v):
    return sum(x * x for x in v) ** 0.5


def _linear_blend(embedding, prior, features):
    graph_signal = min(_norm(embedding.vector) / 4.0, 1.0)
    scalar_signal = min(0.08 * features.obfuscation_count + 0.10 * features.anti_analysis_count + 0.08 * features.suspicious_api_count + (0.10 if features.self_signed else 0.0), 1.0)
    components = {"bayesian_prior": prior.p_high, "rgcn_embedding_signal": graph_signal, "static_scalars": scalar_signal}
    score = 0.45 * prior.p_high + 0.35 * graph_signal + 0.20 * scalar_signal
    return AggregatedScore(min(score, 1.0), components, "cold_start_fallback")
