"""Reporting & explainability: MITRE mapping, report aggregation, RAG-grounded
GenAI explanations, recommendations."""
from backend.reporting.aggregator import build_report  # noqa: F401
from backend.reporting.genai import explain  # noqa: F401
from backend.reporting.recommendations import build as build_recommendations  # noqa: F401
