"""Variant lineage: cluster DEX-content fuzzy hashes into families.

Turns one known-malicious sample into coverage for its repackaged variants and
avoids redundant sandbox runs at campaign scale.

SAFETY RULE: clusters only ever carry a MALICIOUS verdict. A repackaged bank
app fuzzy-matches the genuine app, so inheriting "benign" through similarity
would wave the impersonator through. Benign verdicts come only from exact
whole-APK SHA-256 matches (see lookup.py).

MVP implementation: greedy online clustering, in memory, rebuilt from the
persistent verdict store at start-up (hashing/verdict_store.py). The similarity
threshold (config `verdict_inheritance_similarity`) is UNCALIBRATED.
TODO: ANN index (e.g. TLSH-tree) for scale.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Optional

from backend.hashing.fuzzy_hash import FuzzyHashes, normalized_similarity

MALICIOUS = "malicious"


def _config_threshold() -> float:
    from config import thresholds

    return float(thresholds()["verdict_inheritance_similarity"])


@dataclass
class Cluster:
    cluster_id: str
    centroid: FuzzyHashes
    members: list[str] = field(default_factory=list)  # sha256s
    malicious: bool = False
    family: Optional[str] = None


class VariantClusterStore:
    """In-memory greedy clustering over DEX-content fuzzy hashes."""

    def __init__(self, similarity_threshold: float | None = None) -> None:
        self.threshold = (similarity_threshold if similarity_threshold is not None
                          else _config_threshold())
        self._clusters: dict[str, Cluster] = {}

    def best_match(self, fuzzy: FuzzyHashes) -> tuple[Optional[str], float]:
        """Closest cluster at or above the threshold. Read-only."""
        if fuzzy.empty:
            return None, 0.0
        best_id, best_sim = None, 0.0
        for cid, cluster in self._clusters.items():
            sim = normalized_similarity(fuzzy, cluster.centroid)
            if sim > best_sim:
                best_id, best_sim = cid, sim
        if best_id is not None and best_sim >= self.threshold:
            return best_id, best_sim
        return None, best_sim

    def malicious_match(self, fuzzy: FuzzyHashes) -> tuple[Optional[str], float]:
        """Closest cluster above the threshold, only if it's flagged malicious."""
        cid, sim = self.best_match(fuzzy)
        if cid is not None and self._clusters[cid].malicious:
            return cid, sim
        return None, sim

    def assign(self, sha256: str, fuzzy: FuzzyHashes,
               new_cluster_id: Optional[str] = None) -> Optional[str]:
        """Add a sample to its closest cluster, or start a new one (named
        `new_cluster_id` when rebuilding from the verdict store). Mutates."""
        if fuzzy.empty:
            return None
        cid, _ = self.best_match(fuzzy)
        if cid is None:
            cid = new_cluster_id if new_cluster_id and new_cluster_id not in self._clusters \
                else f"fam-{uuid.uuid4().hex[:12]}"
            self._clusters[cid] = Cluster(cluster_id=cid, centroid=fuzzy)
        self._clusters[cid].members.append(sha256)
        return cid

    def mark_malicious(self, cluster_id: str, family: Optional[str] = None) -> None:
        cluster = self._clusters.get(cluster_id)
        if cluster is not None:
            cluster.malicious = True
            if family:
                cluster.family = family

    def __len__(self) -> int:
        return len(self._clusters)
