"""Malware family classifier (placeholder model).

Assigns a sample to a known Android banking-malware family (Anubis, Cerberus,
Hydra, SharkBot, TeaBot, Hook, ...) from static + dynamic features. Feeds
attribution + verdict inheritance across a fuzzy-hash cluster.

Placeholder: rule-of-thumb signature matching. 
"""
from __future__ import annotations

from dataclasses import dataclass

KNOWN_FAMILIES = ["Anubis", "Cerberus", "Hydra", "SharkBot", "TeaBot", "Hook", "Unknown"]

# Naive family fingerprints (string markers).
_FAMILY_MARKERS: dict[str, list[str]] = {
    "Anubis": ["anubis", "RECORD_AUDIO", "keylogger"],
    "Cerberus": ["cerberus", "getRunningTasks", "overlay"],
    "SharkBot": ["sharkbot", "ATS", "Automatic Transfer System"],
    "TeaBot": ["teabot", "toddler"],
    "Hook": ["hook", "vnc", "file_manager"],
}


@dataclass
class FamilyPrediction:
    family: str
    confidence: float
    model: str


def classify(strings: list[str]) -> FamilyPrediction:
    joined = "\n".join(strings).lower()
    best, best_hits = "Unknown", 0
    for family, markers in _FAMILY_MARKERS.items():
        hits = sum(1 for m in markers if m.lower() in joined)
        if hits > best_hits:
            best, best_hits = family, hits
    confidence = min(0.4 + 0.2 * best_hits, 0.95) if best_hits else 0.0
    return FamilyPrediction(family=best, confidence=confidence, model="marker_heuristic")
