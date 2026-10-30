"""Static and dynamic risk scoring entry point.

This file bridges the two halves of the project that had diverged from a
common ancestor:

  - the KG -> R-GCN -> Bayesian -> XGBoost stack (the "ml" branch), and
  - the dynamic-evidence bridging (dynamic=/network= re-scoring) that lets a
    sandbox run refine an existing static verdict instead of producing a
    second, disconnected one (the "static-dynamic" branch).

Every model stage (R-GCN embedding, Bayesian prior, XGBoost aggregation)
degrades gracefully to a deterministic cold-start fallback when no trained
artifact is present under /models -- see rgcn.py/_fallback_embedding,
bayesian.py's "expert_fallback", and aggregator.py's "cold_start_fallback".
That fallback does NOT require torch/joblib/xgboost to be importABLE, only
that rgcn.py/bayesian.py/aggregator.py guard those imports (see the
try/except ImportError blocks added to each) -- so this module imports and
runs identically whether or not the [ml] extra is installed; it just scores
with expert priors instead of learned weights until real artifacts exist.

Public interface (kept stable, superset of both branches):
    score_static(bundle: StaticBundle, kg=None, dynamic=None, network=None) -> RiskResult

`backend/orchestration/pipeline.py` already calls this both ways (once
statically in `analyze()`, once with `dynamic=`/`network=` in
`_finalize_sandbox_report()`), so no orchestration changes were required --
only this module needed to speak both dialects at once.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path

from backend.scoring import bayesian, modes, rules_engine
from backend.scoring.aggregator import aggregate, load_model as load_xgb
from backend.scoring.category import infer_category
from backend.scoring.features import build_features, to_scalar_features
from backend.scoring.knowledge_graph import KnowledgeGraph, default_graph
from backend.scoring.rgcn import embed_subgraph, load_model as load_rgcn
from backend.static_analysis import StaticBundle
from config import thresholds

_LOADED_MODEL_DIR: Path | None = None


@dataclass
class ScoreStep:
    """One line of the score's audit trail. The deltas sum to the final score."""
    step: str            # model | kg_context | runtime_* | rule:<id>
    kind: str            # base (model output) | add (bounded bonus) | floor (rule minimum)
    delta: float         # what this step changed (0 when a floor was already exceeded)
    score_after: float
    detail: str


class _Ledger:
    """Applies each scoring step and records its effect, so the report can show
    exactly why the final number is what it is."""

    def __init__(self) -> None:
        self.score = 0.0
        self.steps: list[ScoreStep] = []

    def _record(self, step: str, kind: str, new: float, detail: str) -> None:
        new = min(max(new, 0.0), 1.0)
        self.steps.append(ScoreStep(step, kind, new - self.score, new, detail))
        self.score = new

    def base(self, step: str, value: float, detail: str) -> None:
        self._record(step, "base", value, detail)

    def add(self, step: str, bonus: float, detail: str) -> None:
        capped = " (capped at 1.0)" if self.score + bonus > 1.0 else ""
        self._record(step, "add", self.score + bonus, detail + capped)

    def floor(self, step: str, minimum: float, detail: str) -> None:
        note = "" if minimum > self.score else f" (no effect: score already ≥ {minimum:.2f})"
        self._record(step, "floor", max(self.score, minimum), detail + note)


@dataclass
class RiskResult:
    score: float
    severity: str
    components: dict[str, float]
    capabilities: list[str] = field(default_factory=list)
    rules_triggered: list[rules_engine.RuleHit] = field(default_factory=list)
    needs_dynamic_analysis: bool = False
    verdict_label: str = "unknown"
    contributing_factors: list[str] = field(default_factory=list)
    decision_path: list[str] = field(
        default_factory=lambda: ["static", "knowledge_graph", "rgcn", "bayesian", "xgboost", "rules"]
    )
    category: str | None = None
    dynamic_analysis_used: bool = False
    breakdown: list[ScoreStep] = field(default_factory=list)
    scoring_mode: str = modes.DEFAULT_MODE


def _init_models(mode: str) -> None:
    """Best-effort load of the mode's trained artifacts (ml/models/ or ml/models/retrained/).

    For "model", each load_* call is a no-op when its file or backing package
    (torch/joblib/xgboost) is missing, and scoring falls back to the expert /
    cold-start path. "retrained" refuses to run without its files instead
    (modes.require_models), so it can never silently score with fallback weights.
    Re-loads when the mode's directory changes (e.g. a test or demo switching modes).
    """
    global _LOADED_MODEL_DIR
    model_dir = modes.model_dir(mode)
    if model_dir is None or model_dir == _LOADED_MODEL_DIR:
        return
    modes.require_models(mode)
    load_rgcn(model_dir / "rgcn.pt")
    bayesian.load_model(model_dir / "bayesian.joblib")
    load_xgb(model_dir / "xgboost.json")
    _LOADED_MODEL_DIR = model_dir


# Transparent ("rules") mode: hand-set weights over the same static features the
# model sees. Chosen so that no single kind of evidence reaches "warn" (0.25) on
# its own except together with others, and the sum without any rule stays below
# "block" on the bank SDK (0.60) unless several kinds coincide. To be calibrated
# on the APK test set; they are shown in every report's breakdown.
TRANSPARENT_WEIGHTS = {
    # name: (per item, cap, what is counted)
    "sensitive_permissions": (0.04, 0.20, "sensitive permission(s) (SMS, overlay, accessibility, install, ...)"),
    "suspicious_api_use": (0.05, 0.15, "API use flagged abnormal for the app's category"),
    "anti_analysis": (0.05, 0.15, "anti-analysis technique(s) not common in legitimate apps"),
    "obfuscation": (0.05, 0.10, "obfuscation/packer signal(s)"),
    "debug_certificate": (0.05, 0.05, "signed with the Android debug certificate"),
}


def _transparent_evidence(ledger: "_Ledger", bundle: StaticBundle, scalar) -> None:
    counts = {
        "sensitive_permissions": scalar.sensitive_permission_count,
        "suspicious_api_use": scalar.suspicious_api_count,
        "anti_analysis": sum(1 for f in bundle.anti_analysis.findings if not f.common_in_benign),
        "obfuscation": scalar.obfuscation_count,
        "debug_certificate": int(scalar.debug_signed),
    }
    for name, (per_item, cap, what) in TRANSPARENT_WEIGHTS.items():
        n = counts[name]
        if n:
            ledger.add(f"evidence:{name}", min(per_item * n, cap),
                       f"{n} {what} × {per_item:.2f}, max {cap:.2f}; hand-set.")


def severity_for(score: float) -> str:
    tiers = thresholds()["severity_tiers"]
    for name in ("critical", "high", "medium", "low"):
        band = tiers[name]
        if band["min"] <= score < band["max"]:
            return name
    return "low"


def score_static(bundle: StaticBundle, kg: KnowledgeGraph | None = None,
                 dynamic=None, network=None, mode: str | None = None) -> RiskResult:
    """Score a sample. Called twice per uncertain sample:

      1. From analyze() right after static analysis, with dynamic=None --
         produces the TIER 2 verdict and decides whether to escalate.
      2. From _finalize_sandbox_report() once the sandbox job completes,
         with dynamic=<DynamicBehaviorReport> and network=<[NetworkIndicator]>
         -- re-scores the SAME static bundle, layering runtime evidence on
          on top of the static score instead of producing a second verdict.

    `mode` (rules | model | retrained) defaults to the configured scoring mode
    (backend/scoring/modes.py).
    """
    mode = modes.validate(mode) if mode else modes.current_mode()
    _init_models(mode)
    kg = kg or default_graph()
    manifest = bundle.structural.manifest
    permissions = manifest.permissions
    category = infer_category(bundle)
    features = build_features(bundle, category)

    # 1. Knowledge graph: capabilities + induced (category-aware) subgraph.
    caps = kg.derive_capabilities(permissions, category)
    subgraph = kg.induced_subgraph(permissions, category)

    # 3. Bayesian prior (trained NB if loaded, else expert-weighted fallback). Also
    #    computed in rules mode, only to list the sensitive permissions it weighs.
    prior = bayesian.prior_p_high(permissions, category)
    scalar = to_scalar_features(features)
    # `components` are model inputs/diagnostics; `ledger` is what actually builds
    # the final score, step by step (reported as risk.breakdown).
    ledger = _Ledger()
    if mode == "rules":
        components = {"category_context_available": 1.0 if category else 0.0}
        ledger.base("no_model", 0.0, "Transparent scoring: no ML model. The score is the "
                    "hand-set evidence weights below plus rule minimums.")
        _transparent_evidence(ledger, bundle, scalar)
    else:
        # 2. R-GCN embedding (real model if loaded, else deterministic fallback).
        embedding = embed_subgraph(subgraph)
        # 4. Scalar features + XGBoost aggregation (falls back to a linear blend
        #    of prior/embedding/scalars -- "cold_start_fallback" -- if no
        #    trained XGBoost artifact is loaded). Same scalars as the dataset builder.
        agg = aggregate(embedding, prior, scalar)
        components = dict(agg.components)
        components["model_probability"] = agg.score
        components["category_context_available"] = 1.0 if category else 0.0
        which = "retrained " if mode == "retrained" else ""
        ledger.base("model", agg.score,
                    f"{which}{agg.model} probability (R-GCN embedding + Bayesian prior + "
                    "static features).")

    # Knowledge-graph context bonus: EXPERIMENTAL, off by default (config/thresholds.yaml
    # kg_context_boost). The category is a guess and the edges were hand-written; the
    # remaining edges cite a policy source but none is data-derived yet (planned after
    # later). Off, anomalous capabilities stay in the report as context only.
    anomalous = [c for c in caps if c.context == "ANOMALOUS_FOR"]
    kg_boost = min(0.08 * len(anomalous), 0.24) if anomalous else 0.0
    if kg_boost and thresholds().get("kg_context_boost", False):
        components["kg_anomalous_capabilities"] = kg_boost
        ledger.add("kg_context", kg_boost,
                   f"+0.08 per capability anomalous for category {category} "
                   f"({', '.join(c.capability for c in anomalous)}), max 0.24; hand-set, experimental.")

    # 5. Runtime observations -- additive evidence from the sandbox on top of
    #    the (already category/model-aware) static score. This is the piece
    #    that was missing on the ml branch: dynamic analysis stops being a
    #    second, disconnected verdict and instead refines the same score.
    dynamic_used = dynamic is not None
    if dynamic is not None:
        behavior_count = len(getattr(dynamic, "findings", []))
        network_items = network or []
        c2_exfil_count = sum(
            1 for indicator in network_items
            if getattr(indicator, "is_c2", False) or getattr(indicator, "is_exfil", False)
        )
        overlay_count = getattr(dynamic, "overlay_detected_count", 0)
        components["runtime_behaviors"] = min(0.05 * behavior_count, 0.25)
        components["runtime_network"] = min(0.10 * c2_exfil_count, 0.30)
        components["runtime_overlays"] = min(0.15 * overlay_count, 0.30)
        for key, what in (("runtime_behaviors", f"{behavior_count} runtime behaviour(s) × 0.05, max 0.25"),
                          ("runtime_network", f"{c2_exfil_count} C2/exfil indicator(s) × 0.10, max 0.30"),
                          ("runtime_overlays", f"{overlay_count} overlay attempt(s) × 0.15, max 0.30")):
            if components[key]:
                ledger.add(key, components[key], what + "; hand-set.")

    # 6. Rules: graded evidence (rules_engine.py docstring). Weights first, then
    #    floors, so a floor is a true minimum. Only decisive evidence (R004 package +
    #    certificate impersonation, R005 stage 4-5 behaviour) is a hard override; the
    #    model's probability stays the base, so a low model score is not silently
    #    replaced by permission- or API-presence evidence.
    hits = rules_engine.evaluate(bundle, category)
    for hit in hits:
        if hit.weight:
            ledger.add(f"rule:{hit.rule_id}", hit.weight,
                       f"{hit.rule_id} adds {hit.weight:.2f} (evidence stage {hit.stage}).")
    for hit in hits:
        if hit.min_score:
            kind = ("hard override: no sandbox" if hit.hard_override
                    else "warn-level" if hit.min_score < 0.45 else "minimum")
            ledger.floor(f"rule:{hit.rule_id}", hit.min_score,
                         f"{hit.rule_id} sets a minimum of {hit.min_score:.2f} ({kind}).")
    score = ledger.score

    severity = severity_for(score)
    policy = thresholds()["response_policy"]["default"]
    lo, hi = policy["escalate_to_sandbox_between"]
    # Once dynamic evidence is already folded in, don't ask for another
    # sandbox escalation on the re-score.
    needs_dynamic = (
        not dynamic_used and lo <= score <= hi and not any(h.hard_override for h in hits)
    )
    verdict = _verdict_for(score, severity)

    factors: list[str] = []
    if verdict == "benign" and not bundle.structural.manifest.package_name:
        # Nothing was read, so a low score is absence of evidence, not evidence of
        # safety (malware also uses malformed manifests to break analysers).
        verdict = "unknown"
        factors.append("The manifest could not be parsed, so a low score is not evidence of "
                       "safety; verdict left as unknown.")
    if category:
        factors.append(f"Application category inferred/declared as {category}.")
    for cap in anomalous:
        factors.append(f"Context (not scored): {cap.capability} is marked anomalous for "
                       f"{category or 'unknown'} apps in the knowledge graph.")
    for p in prior.contributing:
        factors.append(f"Sensitive permission contributes to the Bayesian prior: {p}.")
    if dynamic_used:
        factors.append(
            f"Dynamic sandbox evidence incorporated: {len(getattr(dynamic, 'findings', []))} "
            f"runtime behavior(s), {len(network or [])} network indicator(s)."
        )
    for hit in hits:
        factors.append(hit.description)

    return RiskResult(
        score=score,
        severity=severity,
        components=components,
        capabilities=[c.capability for c in caps],
        rules_triggered=hits,
        needs_dynamic_analysis=needs_dynamic,
        verdict_label=verdict,
        contributing_factors=factors,
        category=category,
        dynamic_analysis_used=dynamic_used,
        breakdown=ledger.steps,
        scoring_mode=mode,
        decision_path=(["static", "knowledge_graph", "transparent_weights", "rules"] if mode == "rules"
                       else ["static", "knowledge_graph", "rgcn", "bayesian", "xgboost", "rules"]),
    )


def _verdict_for(score: float, severity: str) -> str:
    if severity in ("high", "critical"):
        return "malicious"
    if severity == "medium":
        return "suspicious"
    return "benign"