"""Shared API helpers: response-policy resolution from config/thresholds.yaml."""
from __future__ import annotations

from config import thresholds


def resolve_action(score: float, touchpoint: str) -> str:
    """Map a risk score -> {allow, warn, block} using the touchpoint's policy band.

    Central, config-driven graduated response (NOT scattered across clients).
    """
    policy_all = thresholds()["response_policy"]
    policy = policy_all.get(touchpoint, policy_all["default"])
    if score < policy["allow_below"]:
        return "allow"
    if score < policy["warn_below"]:
        return "warn"
    return "block"


def human_review_required(score: float) -> bool:
    return score >= thresholds()["human_review_required_at_or_above"]
