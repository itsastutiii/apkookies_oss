"""Hash lookup facade — the fast-path gate used by the pipeline, the browser
extension and the sandbox de-dup check.

Layered lookup (read-only; nothing is stored until record_verdict):
  1. exact whole-APK SHA-256 -> the stored verdict, whatever it is
     (unless it is STALE: made by an older model/config; then it is re-checked).
  2. exact DEX-content SHA-256 -> MALICIOUS only (survives re-zip/re-sign).
  3. DEX-content fuzzy cluster -> MALICIOUS only (repackaged variants).
  4. miss -> caller runs the full static/dynamic pipeline.

SAFETY RULE: a benign verdict is only ever returned for an exact whole-APK
SHA-256 match. A repackaged bank app has the genuine app's code, so it would
match the genuine app at tiers 2–3; inheriting "benign" there would wave the
impersonator through. This also covers analyst overrides: a "benign" override
applies to that exact file only.

Tiers 2–3 are in-memory indexes rebuilt from the persistent VerdictStore, so
they survive restarts. Only current (non-stale, non-cleared) malicious
verdicts feed them, so a cleared or overridden verdict stops spreading at once,
and after retraining old verdicts stop spreading until re-checked.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from backend.hashing import fuzzy_hash
from backend.hashing.clustering import MALICIOUS, VariantClusterStore
from backend.hashing.content_hash import ContentHashes
from backend.hashing.exact_hash import ExactHashes
from backend.hashing.fuzzy_hash import FuzzyHashes
from backend.hashing.verdict_store import StoredVerdict, VerdictStore


@dataclass
class LookupResult:
    hit: bool
    verdict: Optional[str] = None            # benign|suspicious|malicious
    matched_by: Optional[str] = None         # "exact" | "dex_exact" | "fuzzy"
    cluster_id: Optional[str] = None
    similarity: float = 0.0
    inherited_from: Optional[str] = None      # cluster id / sha256
    fuzzy_status: str = "available"           # available | partial | unavailable
    fuzzy_note: Optional[str] = None
    source: Optional[str] = None              # static | sandbox | analyst (of the matched verdict)
    provenance: Optional[dict] = None         # of the matched verdict
    stale_verdict: Optional[str] = None       # exact match existed but was made by an older system


class HashLookupService:
    def __init__(self, store: Optional[VerdictStore] = None,
                 clusters: Optional[VariantClusterStore] = None) -> None:
        self.store = store or VerdictStore(":memory:")
        self._threshold = clusters.threshold if clusters is not None else None
        self.clusters = clusters or VariantClusterStore()
        # DEX-content SHA-256 -> sha256 of the malicious APK it was first seen in.
        self._malicious_dex: dict[str, str] = {}
        self._rebuild()

    # -- read path --------------------------------------------------------
    def lookup(self, exact: ExactHashes, content: Optional[ContentHashes] = None) -> LookupResult:
        fz = fuzzy_hash.status()
        common = dict(fuzzy_status=fz.status, fuzzy_note=fz.note)

        # Tier 1: exact whole-APK hash -> any current stored verdict.
        stale_verdict = None
        stored = self.store.get(exact.sha256)
        if stored is not None:
            if not stored.is_stale(self.store.current_fingerprint):
                return LookupResult(hit=True, verdict=stored.verdict, matched_by="exact",
                                    similarity=1.0, source=stored.source,
                                    provenance=stored.provenance, cluster_id=stored.cluster_id,
                                    **common)
            stale_verdict = stored.verdict

        if content is not None and content.dex_sha256:
            # Tier 2: identical code, different container -> malicious only.
            source = self._malicious_dex.get(content.dex_sha256)
            if source is not None and source != exact.sha256:
                src = self.store.get(source)
                return LookupResult(hit=True, verdict=MALICIOUS, matched_by="dex_exact",
                                    similarity=1.0, inherited_from=source,
                                    source=src.source if src else None,
                                    provenance=src.provenance if src else None, **common)

            # Tier 3: near-identical code -> malicious only.
            cid, sim = self.clusters.malicious_match(content.dex_fuzzy)
            if cid is not None:
                return LookupResult(hit=True, verdict=MALICIOUS, matched_by="fuzzy",
                                    cluster_id=cid, similarity=sim, inherited_from=cid,
                                    stale_verdict=stale_verdict, **common)
            return LookupResult(hit=False, similarity=sim, stale_verdict=stale_verdict, **common)

        return LookupResult(hit=False, stale_verdict=stale_verdict, **common)

    # -- write path -------------------------------------------------------
    def record_verdict(self, sha256: str, verdict: str,
                       content: Optional[ContentHashes] = None,
                       family: Optional[str] = None, *, source: str = "static",
                       fingerprints: Optional[list[str]] = None) -> Optional[str]:
        """Persist a freshly computed verdict; returns the sample's cluster id (if any).

        Every sample joins a cluster (for lineage reporting), but only a malicious
        verdict marks the DEX content / cluster as inheritable. An existing analyst
        verdict is left untouched.
        """
        existed = self.store.get(sha256, include_cleared=True) is not None
        stored = self.store.record(
            sha256, verdict, source,
            dex_sha256=content.dex_sha256 if content else None,
            dex_ssdeep=content.dex_ssdeep if content else None,
            dex_tlsh=content.dex_tlsh if content else None,
            family=family, fingerprints=fingerprints)
        if not stored:
            current = self.store.get(sha256)
            return current.cluster_id if current else None
        if existed:
            # A replaced verdict may have fed the indexes (e.g. stale malicious -> benign).
            self._rebuild()
            row = self.store.get(sha256)
            return row.cluster_id if row else None
        cluster_id = self._index(self.store.get(sha256))  # type: ignore[arg-type]
        self.store.set_cluster(sha256, cluster_id)
        return cluster_id

    def override(self, sha256: str, verdict: str, analyst: str, reason: str) -> StoredVerdict:
        row = self.store.override(sha256, verdict, analyst, reason)
        self._rebuild()
        return row

    def clear(self, sha256: str, analyst: str, reason: str) -> bool:
        changed = self.store.clear(sha256, analyst, reason)
        if changed:
            self._rebuild()
        return changed

    # -- indexes ----------------------------------------------------------
    def _index(self, row: StoredVerdict) -> Optional[str]:
        inheritable = (row.verdict == MALICIOUS
                       and not row.is_stale(self.store.current_fingerprint))
        if inheritable and row.dex_sha256:
            self._malicious_dex.setdefault(row.dex_sha256, row.sha256)
        fuzzy = FuzzyHashes(ssdeep=row.dex_ssdeep, tlsh=row.dex_tlsh)
        cluster_id = self.clusters.assign(row.sha256, fuzzy, new_cluster_id=row.cluster_id)
        if cluster_id is not None and inheritable:
            self.clusters.mark_malicious(cluster_id, row.family)
        return cluster_id

    def _rebuild(self) -> None:
        self.clusters = VariantClusterStore(similarity_threshold=self._threshold)
        self._malicious_dex = {}
        for row in self.store.active():
            cluster_id = self._index(row)
            if cluster_id != row.cluster_id:
                self.store.set_cluster(row.sha256, cluster_id)
