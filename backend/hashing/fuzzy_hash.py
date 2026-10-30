"""Fuzzy hashing: catches repackaged / resigned variants that exact hashing misses.

Two algorithms:
  * TLSH (locality-sensitive hash): PRIMARY. A core dependency (py-tlsh); robust
    distance metric, suits clustering at scale.
  * ssdeep (context-triggered piecewise hashing): optional secondary, used only
    when TLSH can't compare (needs the libfuzzy system library).

Both are guarded imports so the API still boots without them, but their absence is never silent:
`status()` reports it and the pipeline writes it into every report
(`hashes.fuzzy_status` / `hashes.fuzzy_note`). Install: `pip install -e ".[static]"`.

UNCALIBRATED: the TLSH distance -> similarity mapping (config
`tlsh_max_distance`) and the inheritance threshold (`verdict_inheritance_similarity`)
are placeholders until tuned on the APK test set (docs/TESTSET.md).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

try:  # optional
    import ssdeep as _ssdeep
except ImportError:  # pragma: no cover
    _ssdeep = None

try:  # optional
    import tlsh as _tlsh
except ImportError:  # pragma: no cover
    _tlsh = None


@dataclass(frozen=True)
class FuzzyHashes:
    ssdeep: Optional[str]
    tlsh: Optional[str]

    @property
    def empty(self) -> bool:
        return not self.ssdeep and not self.tlsh


@dataclass(frozen=True)
class FuzzyStatus:
    status: str          # "available" | "partial" | "unavailable"
    note: Optional[str]  # human-readable explanation when not fully available


def status() -> FuzzyStatus:
    """Is the primary fuzzy hash (TLSH) installed in this process?"""
    if _tlsh is not None:
        return FuzzyStatus("available", None)  # ssdeep is optional
    if _ssdeep is not None:
        return FuzzyStatus("partial", "Fuzzy hashing partial: py-tlsh (the primary fuzzy hash) "
                                      "is not installed; only ssdeep was used.")
    return FuzzyStatus(
        "unavailable",
        "Fuzzy hashing unavailable: py-tlsh is not installed (nor the optional ssdeep), so "
        "near-duplicate (variant) matching was not performed. Only exact SHA-256 and exact "
        "DEX-content matches were checked.",
    )


def fuzzy_hash_file(path: str | Path) -> FuzzyHashes:
    data = Path(path).read_bytes()
    return fuzzy_hash_bytes(data)


def fuzzy_hash_bytes(data: bytes) -> FuzzyHashes:
    ss = _ssdeep.hash(data) if _ssdeep else None
    tl = None
    if _tlsh:
        # TLSH needs >= 50 bytes and some entropy; guard it.
        try:
            tl = _tlsh.hash(data)
            if tl in ("", "TNULL"):
                tl = None
        except ValueError:  # pragma: no cover
            tl = None
    if not _ssdeep and not _tlsh:
        _warn_unavailable_once()
    return FuzzyHashes(ssdeep=ss, tlsh=tl)


_warned = False


def _warn_unavailable_once() -> None:
    global _warned
    if not _warned:
        logger.warning("Fuzzy hashing unavailable: install py-tlsh (requirements.txt). "
                       "Reports will say so in hashes.fuzzy_status.")
        _warned = True


def _tlsh_max_distance() -> int:
    from config import thresholds

    return int(thresholds().get("tlsh_max_distance", 300))


def ssdeep_similarity(a: str, b: str) -> int:
    """Return ssdeep match score 0..100 (higher = more similar)."""
    if not _ssdeep:
        raise RuntimeError("ssdeep not installed")
    return _ssdeep.compare(a, b)


def tlsh_distance(a: str, b: str) -> int:
    """Return TLSH distance (lower = more similar; 0 = identical)."""
    if not _tlsh:
        raise RuntimeError("py-tlsh not installed")
    return _tlsh.diff(a, b)


def normalized_similarity(a: FuzzyHashes, b: FuzzyHashes) -> float:
    """Combine available fuzzy metrics into a single 0..1 similarity.

    TLSH first (distance mapped to a similarity); ssdeep (0..100) only when TLSH
    can't compare, e.g. a hash is missing because the input was too small.
    Returns 0.0 when no shared algorithm is available.
    """
    if a.tlsh and b.tlsh and _tlsh:
        dist = tlsh_distance(a.tlsh, b.tlsh)
        # TLSH distances run 0..~1000+. Linear map with an UNCALIBRATED cut-off.
        max_dist = _tlsh_max_distance()
        return max(0.0, 1.0 - min(dist, max_dist) / max_dist)
    if a.ssdeep and b.ssdeep and _ssdeep:
        return ssdeep_similarity(a.ssdeep, b.ssdeep) / 100.0
    return 0.0
