"""Small typed in-memory knowledge graph: capabilities, MITRE techniques and category context.

Category edges (NORMAL_FOR / ANOMALOUS_FOR) carry a `source:` and are rejected at
load time without one (see data/knowledge_graph/seed_ontology.yaml). The KG's
score bonus is experimental and off by default (risk_score.py, kg_context_boost);
the graph is otherwise context and explanation in reports.

CURRENT STATE / PLANNED:
- Current: a few hand-picked edges, each citing a Google Play policy; boost off.
- Planned: data-derived edges, e.g. "capability C is anomalous for category K"
  when it is rare in K's benign apps and common in K's malware, measured on
  AndroZoo features with Play categories (ml/eval/benign_firing_rates.py is the
  start), then the boost re-evaluated with/without context edges.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
import yaml

_ONTOLOGY = Path(__file__).resolve().parents[2] / "data" / "knowledge_graph" / "seed_ontology.yaml"

@dataclass
class CapabilityMatch:
    capability: str
    enabling_permissions: list[str]
    context: str
    threat_intent: str | None = None
    mitre_techniques: list[str] = field(default_factory=list)
    match_strength: float = 1.0

class KnowledgeGraph(Protocol):
    def derive_capabilities(self, permissions: list[str], app_category: str | None) -> list[CapabilityMatch]: ...
    def induced_subgraph(self, permissions: list[str], app_category: str | None = None) -> dict: ...

class InMemoryKnowledgeGraph:
    def __init__(self, ontology_path: Path = _ONTOLOGY, partial_match_threshold: float = 0.5) -> None:
        self._o = yaml.safe_load(ontology_path.read_text(encoding="utf-8"))
        self._caps = self._o.get("capabilities", {})
        _require_sources(self._caps)
        self._categories = self._o.get("app_categories", [])
        self._partial_threshold = partial_match_threshold

    def derive_capabilities(self, permissions: list[str], app_category: str | None) -> list[CapabilityMatch]:
        perm_set = set(permissions)
        matches = []
        for cap, spec in self._caps.items():
            required = set(spec.get("enabled_by", []))
            if not required:
                continue
            overlap = required & perm_set
            if not overlap:
                continue
            strength = len(overlap) / len(required)
            if strength < self._partial_threshold:
                continue
            context = "UNKNOWN"
            if app_category:
                category = _canonical_category(app_category)
                if category in edge_categories(spec, "anomalous_for"):
                    context = "ANOMALOUS_FOR"
                elif category in edge_categories(spec, "normal_for"):
                    context = "NORMAL_FOR"
            matches.append(CapabilityMatch(cap, sorted(overlap), context,
                                           spec.get("indicates"), list(spec.get("mitre", [])), strength))
        return matches

    def induced_subgraph(self, permissions: list[str], app_category: str | None = None) -> dict:
        """Build the graph used for both training and runtime scoring.

        CHANGE vs. original: a Capability node (and its edges) is now created
        on *partial* permission overlap (>= partial_match_threshold), not only
        when the full `enabled_by` conjunction is satisfied. The relation type
        used distinguishes full match (ENABLES) from partial match
        (PARTIALLY_ENABLES) so the R-GCN can still tell the difference, but the
        graph is no longer edgeless for the majority of real permission sets --
        previously, most CICMalDroid samples produced zero capability nodes
        because `enabled_by` requires every listed permission simultaneously.
        """
        nodes = [{"id": p, "type": "Permission"} for p in sorted(set(permissions))]
        edges = []
        perm_set = set(permissions)
        if app_category:
            category = _canonical_category(app_category)
            nodes.append({"id": category, "type": "AppCategory"})
        for cap, spec in self._caps.items():
            required = set(spec.get("enabled_by", []))
            if not required:
                continue
            overlap = required & perm_set
            if not overlap:
                continue
            full_match = required.issubset(perm_set)
            strength = len(overlap) / len(required)
            if not full_match and strength < self._partial_threshold:
                continue
            nodes.append({"id": cap, "type": "Capability"})
            rel = "ENABLES" if full_match else "PARTIALLY_ENABLES"
            for p in sorted(overlap):
                edges.append({"src": p, "dst": cap, "rel": rel})
            if app_category:
                category = _canonical_category(app_category)
                ctx_rel = ("ANOMALOUS_FOR" if category in edge_categories(spec, "anomalous_for")
                           else "NORMAL_FOR" if category in edge_categories(spec, "normal_for") else None)
                if ctx_rel:
                    edges.append({"src": cap, "dst": category, "rel": ctx_rel})
            for mitre in spec.get("mitre", []):
                nodes.append({"id": mitre, "type": "MITRETechnique"})
                edges.append({"src": cap, "dst": mitre, "rel": "MAPS_TO_MITRE"})
            if spec.get("indicates"):
                intent = spec["indicates"]
                nodes.append({"id": intent, "type": "ThreatIntent"})
                edges.append({"src": cap, "dst": intent, "rel": "INDICATES"})
        # De-duplicate while preserving order.
        seen = set(); unique_nodes = []
        for n in nodes:
            key = (n["id"], n["type"])
            if key not in seen:
                seen.add(key); unique_nodes.append(n)
        seen_edges = set(); unique_edges = []
        for e in edges:
            key = (e["src"], e["dst"], e["rel"])
            if key not in seen_edges:
                seen_edges.add(key); unique_edges.append(e)
        return {"nodes": unique_nodes, "edges": unique_edges, "category": app_category}


def _edge_entries(spec: dict, key: str) -> list[dict]:
    return [e if isinstance(e, dict) else {"category": e, "source": None} for e in spec.get(key) or []]


def edge_categories(spec: dict, key: str) -> set[str]:
    """Canonical categories of a capability's NORMAL_FOR / ANOMALOUS_FOR edges."""
    return {_canonical_category(e["category"]) for e in _edge_entries(spec, key)}


def _require_sources(caps: dict) -> None:
    for cap, spec in caps.items():
        for key in ("normal_for", "anomalous_for"):
            for e in _edge_entries(spec, key):
                if not (e.get("source") or "").strip():
                    raise ValueError(f"seed ontology: {cap} {key.upper()} {e['category']} has no source:")


def _canonical_category(value: str) -> str:
    """Normalize category spelling/case to the ontology vocabulary."""
    raw = value.strip()
    v = raw.lower().replace("_", " ").replace("-", " ")
    aliases = {
        "social media": "SocialMedia",
        "socialmedia": "SocialMedia",
        "sms": "Communication",
        "messaging": "Communication",
    }
    if v in aliases:
        return aliases[v]
    known = {
        "banking": "Banking", "socialmedia": "SocialMedia", "social media": "SocialMedia",
        "game": "Game", "wallpaper": "Wallpaper", "productivity": "Productivity",
        "communication": "Communication",
    }
    return known.get(v, raw)

def default_graph() -> KnowledgeGraph:
    return InMemoryKnowledgeGraph()