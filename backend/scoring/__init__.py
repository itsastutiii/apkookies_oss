"""Context-aware neuro-symbolic scoring stack:
KG -> R-GCN -> Bayesian prior -> XGBoost aggregator -> rules engine.
"""
from backend.scoring.risk_score import RiskResult, score_static, severity_for  # noqa: F401
