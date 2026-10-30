"""Build a labelled feature dataset from AndroZoo, for retraining the scoring models.

Run this on a disposable Linux VM, never on a personal machine (docs/ANDROZOO.md). It:

  1. --select (also --dry-run), on any machine, no key: samples balanced
     benign/malicious APKs from AndroZoo's public list
     (latest_with-added-date.csv.gz), matched by year AND by store, so neither
     time nor the store can stand in for the label; one APK per package name;
     settled labels preferred. Writes selection.csv + selection.json, which are
     committed: the VM run downloads exactly that list (reproducible, and no
     4 GB list download on the VM);
  2. downloads them (at most 20 at a time, AndroZoo's limit) into a temp folder
     whose total size is capped (default 2 GB);
  3. extracts features with OUR static analysis, the same code live scoring uses
     (backend.static_analysis.run + backend.scoring.features), and records what
     the currently shipped model says, for the before/after comparison;
  4. deletes each APK as soon as its features are extracted;
  5. can be stopped and re-run at any time: it resumes where it left off.

Files in --out (default ml/data/androzoo/), all committed:
  selection.csv       the frozen sample: sha256, label, detections, dates, store
  selection.json      how it was chosen: settings, list file, exclusions, mixes
  features.jsonl.gz   one JSON object per APK: label, dates, features, shipped-model score
  samples.csv         sha256, label, VirusTotal detections, dates, market, status
  DATASET.md          counts, date range, thresholds, exclusions, failures, code version

Labels come from AndroZoo's `vt_detection` (number of VirusTotal engines that
flagged the APK): 0 -> benign, >= 4 -> malicious; 1-3 is a grey zone,
excluded and counted. Benign apps come from the same stores, in the same
proportions, as the malicious ones (a Play-only benign class let "not from
Play" stand in for "malicious").

The AndroZoo API key is personal. It is read only from the ANDROZOO_API_KEY
environment variable, never from the command line (shell history, `ps`), and
is never printed or logged: download errors are recorded as error types only,
because HTTP exceptions include the request URL, which contains the key.

    # select the sample: needs just the public list, no key, downloads no APKs
    python ml/data/build_androzoo_dataset.py --select --list latest_with-added-date.csv.gz
    # full run (on the VM, with ANDROZOO_API_KEY set): downloads the committed selection
    python ml/data/build_androzoo_dataset.py
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import heapq
import io
import json
import logging
import multiprocessing as mp
import os
import re
import shutil
import signal
import sys
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

DOWNLOAD_URL = "https://androzoo.uni.lu/api/download"
MAX_CONCURRENT_DOWNLOADS = 20          # AndroZoo's terms
PLAY = "play.google.com"
# Not app stores: a malware collection, and AndroZoo's "unknown" source. They say
# nothing about where an app was distributed, so they never define its store.
NOT_A_STORE = {"VirusShare", "unknown"}
PLAY_ALIASES = {PLAY, "PlayDrone"}      # PlayDrone = an academic crawl of Google Play
MIN_SCAN_GAP_DAYS_DEFAULT = 90       # ~2x AndroZoo's usual 30-44 day gap between `added` and the VirusTotal scan
RECENT_FROM_YEAR = "2024"               # reported separately: the likely time-aware test years
SAMPLE_COLUMNS = ["sha256", "label", "vt_detection", "vt_scan_date", "added", "dex_date",
                  "apk_size", "markets", "store", "mature", "pkg_hash"]
FAILURE_COLUMNS = ["sha256", "stage", "error"]

log = logging.getLogger("androzoo")


# --------------------------------------------------------------------------- config
@dataclass(frozen=True)
class SampleConfig:
    per_class: int = 2000
    max_apk_mb: float = 30.0
    since: str = "2018-01-01"           # by AndroZoo `added` date, inclusive
    until: str = "2026-04-30"           # inclusive; leave recent months out: VT counts still settling
    benign_max_detections: int = 0
    malicious_min_detections: int = 4
    # Label maturity: VirusTotal detection counts keep rising for months after an app
    # appears, so a recent "0 detections" (or "4") is less settled. APKs whose
    # vt_scan_date is at least this many days after their `added` date are preferred.
    min_scan_gap_days: int = MIN_SCAN_GAP_DAYS_DEFAULT
    seed: int = 20261027

    def label_for(self, vt: int) -> Optional[str]:
        if vt <= self.benign_max_detections:
            return "benign"
        if vt >= self.malicious_min_detections:
            return "malicious"
        return None


@dataclass
class SampleStats:
    rows_read: int = 0
    excluded: Counter = field(default_factory=Counter)
    eligible: Counter = field(default_factory=Counter)      # APKs passing every filter, per class
    candidates: Counter = field(default_factory=Counter)    # distinct packages kept as candidates
    eligible_by_store: Counter = field(default_factory=Counter)   # (label, store)
    eligible_by_cell: Counter = field(default_factory=Counter)    # (label, year, store)

    def as_dict(self) -> dict:
        return {"rows_read": self.rows_read, "excluded": dict(self.excluded),
                "eligible_apks_per_class": dict(self.eligible),
                "candidates_per_class": dict(self.candidates)}


# --------------------------------------------------------------------------- sampling
def _h(seed: int, text: str) -> int:
    """Deterministic, seed-dependent 64-bit hash (uniform ordering for sampling)."""
    return int.from_bytes(hashlib.blake2b(text.encode(), digest_size=8,
                                          key=str(seed).encode()).digest(), "big")


def open_list(path: Path) -> io.TextIOBase:
    raw = gzip.open(path, "rt", encoding="utf-8", newline="") if path.suffix == ".gz" \
        else open(path, encoding="utf-8", newline="")
    return raw


class _BottomK:
    """Uniform random sample of k distinct package names (smallest hash wins).

    A package keeps one representative APK: the one with the smallest hash among
    all its rows that passed the filters. Since the admission threshold only
    falls, a package in the final set was admitted at its first row, so every
    one of its rows was considered.
    """

    def __init__(self, k: int) -> None:
        self.k = k
        self._heap: list[tuple[int, str]] = []          # (-pkg_hash, pkg)
        self.items: dict[str, tuple[int, dict]] = {}     # pkg -> (row_hash, row)

    def offer(self, pkg_h: int, pkg: str, row_h: int, row: dict) -> None:
        if pkg in self.items:
            if row_h < self.items[pkg][0]:
                self.items[pkg] = (row_h, row)
            return
        if len(self._heap) < self.k:
            heapq.heappush(self._heap, (-pkg_h, pkg))
            self.items[pkg] = (row_h, row)
        elif pkg_h < -self._heap[0][0]:
            _, evicted = heapq.heapreplace(self._heap, (-pkg_h, pkg))
            del self.items[evicted]
            self.items[pkg] = (row_h, row)


def store_of(markets: Iterable[str]) -> str:
    """One store per APK, for matching the classes: Google Play if the app is on it
    (PlayDrone is a crawl of Play), else the alphabetically first other store, else
    "none" (e.g. only in VirusShare, a malware collection)."""
    ms = {m.strip() for m in markets if m.strip()} - NOT_A_STORE
    if ms & PLAY_ALIASES:
        return "play"
    return sorted(ms)[0] if ms else "none"


def _scan_gap_days(row: dict, added: date) -> Optional[int]:
    try:
        return (date.fromisoformat((row.get("vt_scan_date") or "")[:10]) - added).days
    except ValueError:
        return None


Cell = tuple[str, str, str, bool]       # (label, year, store, mature)


def iter_candidates(rows: Iterable[dict], cfg: SampleConfig, stats: SampleStats
                    ) -> dict[Cell, _BottomK]:
    """Candidate pools per (label, year, store, mature). Per-year pools matter: recent
    malicious APKs with enough detections are scarce in AndroZoo, and one pool per
    class would leave the newest years (the time-aware test set) with almost nothing.
    Per-store pools let benign apps be drawn from the same stores as malicious ones.
    Mature/immature pools let settled labels be preferred without discarding the rest."""
    since, until = date.fromisoformat(cfg.since), date.fromisoformat(cfg.until)
    max_bytes = int(cfg.max_apk_mb * 1024 * 1024)
    pools: dict[Cell, _BottomK] = {}
    for row in rows:
        stats.rows_read += 1
        vt_raw = (row.get("vt_detection") or "").strip()
        if not vt_raw:
            stats.excluded["no_virustotal_result"] += 1
            continue
        try:
            vt, size = int(vt_raw), int(row["apk_size"])
            added = date.fromisoformat(row["added"][:10])
        except (ValueError, KeyError, TypeError):
            stats.excluded["unparseable_row"] += 1
            continue
        if not since <= added <= until:
            stats.excluded["outside_date_range"] += 1
            continue
        if size > max_bytes:
            stats.excluded["larger_than_size_cap"] += 1
            continue
        label = cfg.label_for(vt)
        if label is None:
            stats.excluded["grey_zone_detections"] += 1
            continue
        pkg = (row.get("pkg_name") or "").strip().strip('"')
        if not pkg:
            stats.excluded["no_package_name"] += 1
            continue
        markets = (row.get("markets") or "").split("|")
        store = store_of(markets)
        if store == "none":
            # No store to match against: benign files from a malware collection are
            # not trustworthy negatives, so malware known only from VirusShare has
            # no benign counterpart and would make "no store" a label shortcut.
            stats.excluded["no_store_to_match"] += 1
            continue
        gap = _scan_gap_days(row, added)
        mature = gap is not None and gap >= cfg.min_scan_gap_days
        sha = row["sha256"].strip().lower()
        year = str(added.year)
        stats.eligible[label] += 1
        stats.eligible_by_store[(label, store)] += 1
        stats.eligible_by_cell[(label, year, store)] += 1
        pool = pools.setdefault((label, year, store, mature), _BottomK(cfg.per_class))
        pool.offer(_h(cfg.seed, f"pkg:{pkg}"), pkg, _h(cfg.seed, f"apk:{sha}"), {
            "sha256": sha, "label": label, "vt_detection": vt,
            "vt_scan_date": row.get("vt_scan_date", ""), "added": row["added"][:19],
            "dex_date": row.get("dex_date", ""), "apk_size": size,
            "markets": "|".join(sorted({m for m in markets if m})), "store": store,
            "mature": int(mature),
            # Hashed so the committed files group by package without listing package names.
            "pkg_hash": hashlib.sha256(pkg.encode()).hexdigest()[:16],
        })
    return pools


def _water_fill(capacity: dict[str, int], total: int) -> dict[str, int]:
    """Spread `total` as evenly as possible over years, each capped by its capacity;
    what a small year can't take goes to the others."""
    quota = {y: 0 for y in capacity}
    remaining = total
    open_years = sorted(capacity, key=lambda y: capacity[y])
    while remaining > 0 and open_years:
        share = max(remaining // len(open_years), 1)
        for y in list(open_years):
            take = min(share, capacity[y] - quota[y], remaining)
            quota[y] += take
            remaining -= take
            if quota[y] >= capacity[y]:
                open_years.remove(y)
            if remaining == 0:
                break
        open_years.sort(key=lambda y: (capacity[y] - quota[y], y))
    return quota


def _proportional_fill(weights: dict[str, int], caps: dict[str, int], total: int) -> dict[str, int]:
    """Split `total` in proportion to `weights` (largest remainder), each key capped by
    `caps`; what a capped key can't take is re-split over the others."""
    quota = {k: 0 for k in weights}
    remaining = min(total, sum(caps[k] for k in weights))
    while remaining > 0:
        open_keys = [k for k in weights if quota[k] < caps[k] and weights[k] > 0]
        if not open_keys:
            break
        w = sum(weights[k] for k in open_keys)
        raw = {k: remaining * weights[k] / w for k in open_keys}
        share = {k: int(raw[k]) for k in open_keys}
        for k in sorted(open_keys, key=lambda k: (share[k] - raw[k], k))[:remaining - sum(share.values())]:
            share[k] += 1
        # The shares add up to `remaining`, so each round either finishes or caps a key.
        for k in open_keys:
            take = min(share[k], caps[k] - quota[k])
            quota[k] += take
            remaining -= take
    return quota


def allocate(pools: dict[Cell, _BottomK], stats: SampleStats, per_class: int, seed: int
             ) -> tuple[list[dict], dict]:
    """Same number of benign and malicious APKs in every (year, store) cell. Years are
    spread as evenly as availability allows; within a year, stores follow the
    malicious class's real store mix (capped by what benign can match). One APK per
    package within a class; settled labels (mature) first."""
    cand: dict[tuple[str, str], dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for (lbl, year, store, mature), pool in pools.items():
        cand[(year, store)][lbl].extend(row for _, row in pool.items.values())
    for cell in cand.values():
        for lbl, rows in cell.items():
            # Mature first; a package in both pools keeps its mature APK.
            rows.sort(key=lambda r: (-r["mature"], _h(seed, "pick:" + r["sha256"])))
            seen, uniq = set(), []
            for r in rows:
                if r["pkg_hash"] not in seen:
                    seen.add(r["pkg_hash"])
                    uniq.append(r)
            cell[lbl] = uniq
    stats.candidates.update({lbl: sum(len(c[lbl]) for c in cand.values())
                             for lbl in ("benign", "malicious")})
    cap = {k: min(len(v["benign"]), len(v["malicious"])) for k, v in cand.items()}
    years = sorted({y for y, _ in cand})
    year_cap = {y: sum(c for (yy, _), c in cap.items() if yy == y) for y in years}
    year_quota = _water_fill(year_cap, per_class)
    chosen: list[dict] = []
    taken: dict[tuple[str, str], int] = {}
    seen_pkgs: dict[str, set] = {"benign": set(), "malicious": set()}
    # Newest years first, so a package seen in several years stays in the scarce recent ones.
    for y in sorted(years, reverse=True):
        stores = [s for (yy, s) in cand if yy == y]
        quota = _proportional_fill({s: stats.eligible_by_cell[("malicious", y, s)] for s in stores},
                                   {s: cap[(y, s)] for s in stores}, year_quota[y])
        for s in stores:
            picks = {lbl: [r for r in cand[(y, s)][lbl] if r["pkg_hash"] not in seen_pkgs[lbl]][:quota[s]]
                     for lbl in ("benign", "malicious")}
            n = min(len(picks["benign"]), len(picks["malicious"]))
            for lbl in ("benign", "malicious"):
                for r in picks[lbl][:n]:
                    seen_pkgs[lbl].add(r["pkg_hash"])
                    chosen.append(r)
            if n:
                taken[(y, s)] = n
    chosen.sort(key=lambda r: (r["added"], r["sha256"]))
    per_year = {}
    for y in years:
        rows_y = [r for r in chosen if r["added"][:4] == y]
        per_year[y] = {
            "benign_candidates": sum(len(cand[(y, s)]["benign"]) for (yy, s) in cand if yy == y),
            "malicious_candidates": sum(len(cand[(y, s)]["malicious"]) for (yy, s) in cand if yy == y),
            "taken_per_class": sum(n for (yy, _), n in taken.items() if yy == y),
            "mature": {lbl: sum(1 for r in rows_y if r["label"] == lbl and int(r["mature"]))
                       for lbl in ("benign", "malicious")},
        }
    return chosen, per_year


def _store_mix(chosen: list[dict], stats: SampleStats) -> dict:
    out = {}
    for store in sorted({s for (_, s) in stats.eligible_by_store}):
        out[store] = {
            "eligible_benign": stats.eligible_by_store[("benign", store)],
            "eligible_malicious": stats.eligible_by_store[("malicious", store)],
            "selected_per_class": sum(1 for r in chosen if r["store"] == store and r["label"] == "malicious"),
        }
    return out


def sample(list_path: Path, cfg: SampleConfig) -> tuple[list[dict], dict]:
    stats = SampleStats()
    t0 = time.time()
    with open_list(list_path) as fh:
        pools = iter_candidates(csv.DictReader(fh), cfg, stats)
    chosen, per_year = allocate(pools, stats, cfg.per_class, cfg.seed)
    counts = Counter(r["label"] for r in chosen)
    recent = [r for r in chosen if r["added"][:4] >= RECENT_FROM_YEAR]
    summary = {
        "list_file": list_path.name,
        "config": asdict(cfg),
        **stats.as_dict(),
        "selected": dict(counts),
        "shortfall_per_class": {lbl: cfg.per_class - counts.get(lbl, 0) for lbl in ("benign", "malicious")},
        "per_year": per_year,
        "stores": _store_mix(chosen, stats),
        "label_maturity": {
            "rule": f"vt_scan_date at least {cfg.min_scan_gap_days} days after added",
            "mature_per_class": {lbl: sum(1 for r in chosen if r["label"] == lbl and int(r["mature"]))
                                 for lbl in ("benign", "malicious")},
            f"recent_{RECENT_FROM_YEAR}_on": {
                lbl: {"selected": sum(1 for r in recent if r["label"] == lbl),
                      "mature": sum(1 for r in recent if r["label"] == lbl and int(r["mature"]))}
                for lbl in ("benign", "malicious")},
        },
        "added_range": _range(r["added"][:10] for r in chosen),
        "vt_scan_range": _range((r["vt_scan_date"] or "")[:10] for r in chosen),
        "malicious_markets": dict(Counter(m for r in chosen if r["label"] == "malicious"
                                          for m in r["markets"].split("|")).most_common(12)),
        "play_only_malicious": sum(1 for r in chosen if r["label"] == "malicious"
                                   and set(r["markets"].split("|")) <= PLAY_ALIASES),
        "apk_mb": _size_summary(chosen),
        "sampling_seconds": round(time.time() - t0, 1),
    }
    return chosen, summary


def _range(values: Iterable[str]) -> list[Optional[str]]:
    vals = sorted(v for v in values if v)
    return [vals[0], vals[-1]] if vals else [None, None]


def _size_summary(rows: list[dict]) -> dict:
    out = {}
    for lbl in ("benign", "malicious"):
        sizes = sorted(r["apk_size"] / 1048576 for r in rows if r["label"] == lbl)
        if sizes:
            out[lbl] = {"median": round(sizes[len(sizes) // 2], 1),
                        "max": round(sizes[-1], 1), "total_gb": round(sum(sizes) / 1024, 2)}
    return out


# --------------------------------------------------------------------------- extraction
def extract_features(apk_path: str) -> dict:
    """Features of one APK via the live static-analysis + scoring code path."""
    from backend.common import provenance
    from backend.scoring.aggregator import scalar_vector
    from backend.scoring.features import build_features, to_scalar_features
    from backend.scoring.risk_score import score_static
    from backend.static_analysis import run as run_static
    from backend.hashing.content_hash import content_hashes

    bundle = run_static(apk_path)
    feats = build_features(bundle, bundle.category)
    scalars = to_scalar_features(feats)
    m = bundle.structural.manifest
    risk = score_static(bundle, mode="model")      # always the shipped model, whatever is configured
    content = content_hashes(apk_path)
    return {
        "category": bundle.category,
        "category_source": bundle.category_source,
        "permissions": list(feats.permissions),
        "scalars": dict(zip(_SCALAR_NAMES, scalar_vector(scalars))),
        "api_rules": sorted({o.marker for o in bundle.api_usage.observations}),
        "api_suspicious": sorted({o.marker for o in bundle.api_usage.observations if o.suspicious}),
        "anti_analysis": sorted({f.technique for f in bundle.anti_analysis.findings}),
        "obfuscation": sorted(set(bundle.code_intel.obfuscation)),
        "ioc_counts": feats.ioc_counts,
        "component_counts": dict(Counter(c.kind for c in m.components)) if m.components else {},
        "exported_components": feats.exported_component_count,
        "min_sdk": m.min_sdk, "target_sdk": m.target_sdk,
        "debuggable": m.debuggable, "allow_backup": m.allow_backup,
        "custom_permission_count": len(m.custom_permissions),
        "debug_signed": bool(bundle.structural.signing.debug_signed),
        "cert_sha256": bundle.structural.signing.fingerprints,
        "dex_count": content.dex_count, "dex_tlsh": content.dex_tlsh,
        "analysis_status": {k: v.get("status") for k, v in bundle.analysis_status.items()},
        "shipped_model": {
            "score": risk.score, "verdict": risk.verdict_label,
            "model_probability": risk.components.get("model_probability"),
            "rules": [h.rule_id for h in risk.rules_triggered],
            "fingerprint": provenance.current(mode="model")["fingerprint"],
        },
    }


_SCALAR_NAMES = [
    "obfuscation_count", "anti_analysis_count", "suspicious_api_count", "self_signed",
    "debug_signed", "exported_component_count", "sms_api_count", "accessibility_api_count",
    "overlay_api_count", "network_api_count", "telephony_api_count", "webview_api_count",
    "crypto_api_count", "telegram_token_count", "domain_count", "ip_count", "url_count",
    "permission_count", "sensitive_permission_count",
]


class _Timeout(Exception):
    pass


def _alarm(signum, frame):  # pragma: no cover - fires only on a hung analysis
    raise _Timeout()


def _worker_init() -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)     # the parent handles Ctrl-C
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _alarm)
    logging.disable(logging.CRITICAL)                # androguard is very chatty
    try:
        from loguru import logger
        logger.remove()
    except ImportError:
        pass


def _extract_and_delete(apk_path: str, timeout: int) -> tuple[str, Optional[dict], Optional[str], float]:
    """Runs in a worker process. ALWAYS deletes the APK, whatever happens."""
    t0 = time.time()
    sha = Path(apk_path).stem
    try:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(timeout)
        return sha, extract_features(apk_path), None, time.time() - t0
    except _Timeout:
        return sha, None, "timeout", time.time() - t0
    except BaseException as e:   # noqa: BLE001 - any analyser crash is a per-sample failure
        return sha, None, type(e).__name__, time.time() - t0
    finally:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)
        try:
            os.unlink(apk_path)
        except OSError:
            pass


# --------------------------------------------------------------------------- downloading
class ByteBudget:
    """Caps the bytes of APKs on disk at once (downloading + waiting + analysing)."""

    def __init__(self, limit: int) -> None:
        self.limit, self.used = limit, 0
        self._cv = threading.Condition()

    def acquire(self, n: int) -> None:
        n = min(n, self.limit)
        with self._cv:
            self._cv.wait_for(lambda: self.used + n <= self.limit)
            self.used += n

    def release(self, n: int) -> None:
        with self._cv:
            self.used -= min(n, self.limit)
            self._cv.notify_all()


def download(client, key: str, sha256: str, dest: Path, retries: int = 3) -> Optional[str]:
    """Download one APK and verify its SHA-256. Returns None on success or an
    error label. Never lets an exception (which would carry the URL, and so
    the key) escape or be logged."""
    part = dest.with_suffix(".part")
    for attempt in range(retries):
        error = None
        try:
            digest = hashlib.sha256()
            with client.stream("GET", DOWNLOAD_URL, params={"apikey": key, "sha256": sha256}) as r:
                if r.status_code != 200:
                    error = f"http_{r.status_code}"
                else:
                    with open(part, "wb") as fh:
                        for chunk in r.iter_bytes(1 << 20):
                            digest.update(chunk)
                            fh.write(chunk)
            if error is None:
                if digest.hexdigest() != sha256:
                    error = "sha256_mismatch"
                else:
                    part.rename(dest)
                    return None
        except Exception as e:   # noqa: BLE001
            error = type(e).__name__
        finally:
            part.unlink(missing_ok=True)
        if error in ("http_404", "http_401", "http_403", "sha256_mismatch"):
            return error
        time.sleep(2 ** attempt * 5)
    return error


# --------------------------------------------------------------------------- state files
def _read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _write_csv(path: Path, rows: list[dict], columns: list[str]) -> None:
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        # LF, not csv's default CRLF: committed files must be byte-identical on every OS.
        w = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    tmp.replace(path)


def _repair_partial(path: Path) -> None:
    """Cut a line left half-written by a crash, so the next append starts cleanly."""
    if not path.exists():
        return
    data = path.read_bytes()
    if data and not data.endswith(b"\n"):
        path.write_bytes(data[:data.rfind(b"\n") + 1])


def _done_shas(features_path: Path) -> set[str]:
    done = set()
    if features_path.exists():
        with features_path.open(encoding="utf-8") as fh:
            for line in fh:
                try:
                    done.add(json.loads(line)["sha256"])
                except (ValueError, KeyError):
                    continue    # a line cut off by a crash; that sample is redone
    return done


@dataclass
class Run:
    work: Path
    out: Path

    @property
    def selection_csv(self) -> Path: return self.out / "selection.csv"
    @property
    def selection_json(self) -> Path: return self.out / "selection.json"
    @property
    def selection_stamp(self) -> Path: return self.work / "selection.sha256"
    @property
    def partial(self) -> Path: return self.work / "features.partial.jsonl"
    @property
    def failures(self) -> Path: return self.work / "failures.csv"
    @property
    def apk_dir(self) -> Path: return self.work / "apks"


def _clean_apk_dir(run: Run) -> None:
    """Leftovers from an interrupted run are our own downloads: delete them."""
    if run.apk_dir.exists():
        shutil.rmtree(run.apk_dir)
    run.apk_dir.mkdir(parents=True)


def download_and_extract(run: Run, rows: list[dict], *, concurrency: int, extract_workers: int,
                         temp_budget_gb: float, timeout: int, retry_failed: bool) -> None:
    import httpx

    key = os.environ.get("ANDROZOO_API_KEY", "").strip()
    if not key:
        raise SystemExit("ANDROZOO_API_KEY is not set. Set it in this shell (see docs/ANDROZOO.md); "
                         "it is never accepted on the command line.")
    if not 1 <= concurrency <= MAX_CONCURRENT_DOWNLOADS:
        raise SystemExit(f"--concurrency must be 1..{MAX_CONCURRENT_DOWNLOADS} (AndroZoo's limit)")
    # httpx logs request URLs (which contain the key) at INFO/DEBUG.
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)

    _repair_partial(run.partial)
    done = _done_shas(run.partial)
    failures = {r["sha256"]: r for r in _read_csv(run.failures)}
    if retry_failed:
        failures = {}
    todo = [r for r in rows if r["sha256"] not in done and r["sha256"] not in failures]
    log.info("%d selected, %d already extracted, %d failed earlier, %d to do",
             len(rows), len(done), len(failures), len(todo))
    if not todo:
        return
    _clean_apk_dir(run)
    budget = ByteBudget(int(temp_budget_gb * 1024 ** 3))
    lock = threading.Lock()
    by_sha = {r["sha256"]: r for r in todo}
    progress = Counter()

    def fail(sha: str, stage: str, error: str) -> None:
        with lock:
            failures[sha] = {"sha256": sha, "stage": stage, "error": error}
            _write_csv(run.failures, list(failures.values()), FAILURE_COLUMNS)
            progress["failed"] += 1

    def on_result(result) -> None:
        sha, feats, error, seconds = result
        budget.release(int(by_sha[sha]["apk_size"]))
        if feats is None:
            fail(sha, "extract", error or "unknown")
            return
        row = by_sha[sha]
        record = {"sha256": sha, "label": row["label"], "added": row["added"],
                  "vt_detection": int(row["vt_detection"]), "vt_scan_date": row["vt_scan_date"],
                  "extract_seconds": round(seconds, 1), "features": feats}
        with lock:
            with run.partial.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            progress["ok"] += 1
            n = progress["ok"] + progress["failed"]
            if n % 25 == 0 or n == len(todo):
                log.info("%d/%d done (%d ok, %d failed), temp in use %.0f MB", n, len(todo),
                         progress["ok"], progress["failed"], budget.used / 1048576)

    ctx = mp.get_context("spawn")       # fresh interpreters: no inherited locks/threads
    pool = ctx.Pool(extract_workers, initializer=_worker_init, maxtasksperchild=50)
    pending = []

    def fetch(row: dict) -> None:
        sha, size = row["sha256"], int(row["apk_size"])
        budget.acquire(size)
        dest = run.apk_dir / f"{sha}.apk"
        error = download(client, key, sha, dest)
        if error is not None:
            budget.release(size)
            fail(sha, "download", error)
            return
        pending.append(pool.apply_async(_extract_and_delete, (str(dest), timeout),
                                        callback=on_result,
                                        error_callback=lambda e, s=sha, n=size: (
                                            budget.release(n), fail(s, "extract", type(e).__name__))))

    try:
        with httpx.Client(timeout=httpx.Timeout(60.0), follow_redirects=True) as client, \
                ThreadPoolExecutor(max_workers=concurrency) as threads:
            list(threads.map(fetch, todo))
        pool.close()
        pool.join()
    except KeyboardInterrupt:
        log.warning("interrupted; deleting temporary APKs. Re-run the same command to resume.")
        pool.terminate()
        raise
    finally:
        pool.terminate()
        shutil.rmtree(run.apk_dir, ignore_errors=True)


# --------------------------------------------------------------------------- outputs
def finalize(run: Run, rows: list[dict], summary: dict, args) -> dict:
    from backend.common import provenance

    run.out.mkdir(parents=True, exist_ok=True)
    records = {}
    if run.partial.exists():
        with run.partial.open(encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                records[rec["sha256"]] = rec
    failures = {r["sha256"]: r for r in _read_csv(run.failures)}
    selected = {r["sha256"] for r in rows}
    with gzip.open(run.out / "features.jsonl.gz", "wt", encoding="utf-8") as fh:
        for sha in sorted(records):
            if sha in selected:
                fh.write(json.dumps(records[sha], sort_keys=True) + "\n")
    sample_rows = []
    for r in rows:
        status = "ok" if r["sha256"] in records else (
            f"failed:{failures[r['sha256']]['stage']}" if r["sha256"] in failures else "pending")
        sample_rows.append({**r, "status": status})
    _write_csv(run.out / "samples.csv", sample_rows, SAMPLE_COLUMNS + ["status"])

    ok = Counter(r["label"] for r in sample_rows if r["status"] == "ok")
    prov = provenance.current(mode="model")      # features record the shipped model's output
    description = {
        **summary,
        "extracted_ok": dict(ok),
        "failures_by_stage_and_error": dict(Counter(f"{f['stage']}:{f['error']}" for f in failures.values()
                                                    if f["sha256"] in selected)),
        "pending": sum(1 for r in sample_rows if r["status"] == "pending"),
        "labels": {"benign": f"vt_detection <= {summary['config']['benign_max_detections']}, "
                             "from the same stores in the same proportions as malicious",
                   "malicious": f"vt_detection >= {summary['config']['malicious_min_detections']}",
                   "excluded": "grey zone between the two, counted under excluded"},
        "extraction": {"code_version": prov["code_version"], "scoring_version": prov["scoring_version"],
                       "shipped_model_fingerprint": prov["fingerprint"], "timeout_seconds": args.timeout,
                       "quark": "not run"},
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    (run.out / "DATASET.md").write_text(render_description(description), encoding="utf-8")
    return description


def render_description(d: dict) -> str:
    cfg = d["config"]
    lines = [
        "# AndroZoo feature dataset",
        "",
        "Built by `ml/data/build_androzoo_dataset.py`. Source: AndroZoo (see README for citations). "
        "Research and non-commercial use only; APKs are not redistributed, only features derived from them.",
        "",
        f"- **Selected:** {d['selected'].get('benign', 0)} benign, {d['selected'].get('malicious', 0)} malicious "
        f"(target {cfg['per_class']} per class; shortfall {d['shortfall_per_class']}).",
        f"- **Extracted OK:** {d.get('extracted_ok', {})}; pending: {d.get('pending', 'n/a')}.",
        f"- **Labels:** benign = {d['labels']['benign']}; malicious = {d['labels']['malicious']}; "
        f"{d['labels']['excluded']}.",
        f"- **Dates (AndroZoo `added`):** filter {cfg['since']} → {cfg['until']}; selected range "
        f"{d['added_range'][0]} → {d['added_range'][1]}. VirusTotal scan dates {d['vt_scan_range'][0]} → "
        f"{d['vt_scan_range'][1]}.",
        f"- **APK size cap:** {cfg['max_apk_mb']} MB. One APK per package name. Seed {cfg['seed']}.",
        f"- **Label maturity:** {_maturity_line(d)}",
        f"- **Play-only malicious APKs:** {d.get('play_only_malicious', 'n/a')} (report results on them separately).",
        f"- **List:** `{d['list_file']}`; {d['rows_read']:,} rows read.",
        f"- **Extraction code:** commit `{d['extraction']['code_version']}`, scoring version "
        f"`{d['extraction']['scoring_version']}`, shipped-model fingerprint "
        f"`{d['extraction']['shipped_model_fingerprint']}`.",
        "",
        "## Per year (equal benign and malicious counts per year)",
        "",
        "Candidates are distinct packages, capped per class, year, store and label maturity.",
        "",
        "| year | benign candidates | malicious candidates | taken per class | mature benign | mature malicious |",
        "|---|---|---|---|---|---|",
        *[f"| {y} | {v['benign_candidates']} | {v['malicious_candidates']} | {v['taken_per_class']} | "
          f"{v.get('mature', {}).get('benign', '')} | {v.get('mature', {}).get('malicious', '')} |"
          for y, v in d["per_year"].items()],
        "",
        "## Stores (equal benign and malicious counts per store and year)",
        "",
        "| store | eligible benign | eligible malicious | selected per class |",
        "|---|---|---|---|",
        *[f"| {k} | {v['eligible_benign']:,} | {v['eligible_malicious']:,} | {v['selected_per_class']} |"
          for k, v in sorted(d.get("stores", {}).items(), key=lambda kv: -kv[1]["selected_per_class"])],
        "",
        "## Excluded while sampling",
        "",
        *[f"- {k.replace('_', ' ')}: {v:,}" for k, v in sorted(d["excluded"].items())],
        "",
        "## Failures",
        "",
        *([f"- {k}: {v}" for k, v in sorted(d.get("failures_by_stage_and_error", {}).items())] or ["- none"]),
        "",
        "## Machine-readable",
        "",
        "```json",
        json.dumps(d, indent=2, sort_keys=True, default=str),
        "```",
        "",
    ]
    return "\n".join(lines)


def _maturity_line(d: dict) -> str:
    m = d.get("label_maturity")
    if not m:
        return "n/a"
    recent = next((k for k in m if k.startswith("recent_")), None)
    line = (f"{m['rule']} preferred; mature: {m['mature_per_class']}.")
    if recent:
        r = m[recent]
        line += (f" From {recent.split('_')[1]} on, {r['benign']['mature']}/{r['benign']['selected']} benign "
                 f"and {r['malicious']['mature']}/{r['malicious']['selected']} malicious are mature. "
                 "Limitation: labels of recent apps are less settled (detections keep rising for months).")
    return line


# --------------------------------------------------------------------------- checking
_PATH_LIKE = re.compile(r"[A-Za-z]:\\|/Users/|/home/|/root/|/tmp/|\\\\")


def check_outputs(out: Path) -> list[str]:
    """Problems that should stop a commit of the output files (empty = OK)."""
    problems = []
    names = ("selection.csv", "selection.json", "features.jsonl.gz", "samples.csv", "DATASET.md")
    missing = [n for n in names if not (out / n).exists()]
    if missing:
        return [f"missing {', '.join(missing)} in {out.name}/"]
    optional = ("vt_refreshed.csv",)        # ml/data/refresh_vt_labels.py, if someone runs it
    extra = sorted(p.name for p in out.iterdir() if p.name not in names + optional)
    if extra:
        problems.append(f"unexpected files in the output folder (don't commit them): {extra}")
    if any(p.suffix.lower() in (".apk", ".dex", ".part") for p in out.rglob("*")):
        problems.append("an APK/DEX/partial download is in the output folder")
    samples = _read_csv(out / "samples.csv")
    ok = {r["sha256"] for r in samples if r.get("status") == "ok"}
    seen = set()
    with gzip.open(out / "features.jsonl.gz", "rt", encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            rec = json.loads(line)
            if rec.get("label") not in ("benign", "malicious") or "features" not in rec:
                problems.append(f"features line {n}: missing label or features")
            seen.add(rec.get("sha256"))
    if seen != ok:
        problems.append(f"features.jsonl.gz has {len(seen)} APKs but samples.csv marks {len(ok)} as ok")
    if {r["sha256"] for r in samples} != {r["sha256"] for r in _read_csv(out / "selection.csv")}:
        problems.append("samples.csv doesn't cover exactly the APKs in selection.csv")
    for r in samples:
        if not re.fullmatch(r"[0-9a-f]{64}", r.get("sha256", "")):
            problems.append(f"samples.csv: bad sha256 {r.get('sha256', '')[:20]!r}")
            break
    key = os.environ.get("ANDROZOO_API_KEY", "").strip()
    for name in names:
        data = (gzip.open(out / name, "rt", encoding="utf-8").read() if name.endswith(".gz")
                else (out / name).read_text(encoding="utf-8"))
        if key and key in data:
            problems.append(f"{name} contains the API key")
        if _PATH_LIKE.search(data):
            problems.append(f"{name} contains something that looks like a local file path")
    return problems


# --------------------------------------------------------------------------- main
def _config_from(args) -> SampleConfig:
    return SampleConfig(per_class=args.per_class, max_apk_mb=args.max_apk_mb, since=args.since,
                        until=args.until, benign_max_detections=args.benign_max_detections,
                        malicious_min_detections=args.malicious_min_detections,
                        min_scan_gap_days=args.min_scan_gap_days, seed=args.seed)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 22), b""):
            digest.update(chunk)
    return digest.hexdigest()


def select(run: Run, args) -> dict:
    """Choose the sample from AndroZoo's list and write selection.csv/.json to --out."""
    if not args.list:
        raise SystemExit("--select needs --list (path to latest_with-added-date.csv.gz)")
    if run.selection_csv.exists() and not args.replace_selection:
        raise SystemExit(f"{run.selection_csv.name} already exists in {run.out.name}/. The VM run "
                         "downloads exactly that list; pass --replace-selection to choose a new one.")
    list_path = Path(args.list)
    rows, summary = sample(list_path, _config_from(args))
    # Identifies the exact list version, since AndroZoo rewrites it daily.
    summary["list_bytes"] = list_path.stat().st_size
    summary["list_sha256"] = _file_sha256(list_path)
    summary["selected_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    run.out.mkdir(parents=True, exist_ok=True)
    _write_csv(run.selection_csv, rows, SAMPLE_COLUMNS)
    run.selection_json.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def load_selection(run: Run) -> tuple[list[dict], dict]:
    """The committed sample. A run's progress is tied to it: if it changes, the old
    progress in --work-dir no longer matches and the run refuses to mix them."""
    if not (run.selection_csv.exists() and run.selection_json.exists()):
        raise SystemExit(f"No selection.csv/selection.json in {run.out}. Pull the repo (they are "
                         "committed), or create them with --select --list ...")
    stamp = _file_sha256(run.selection_csv)
    if run.selection_stamp.exists() and run.selection_stamp.read_text().strip() != stamp:
        raise SystemExit(f"{run.work} holds progress for a different selection.csv. "
                         "Use a new --work-dir for this one.")
    run.work.mkdir(parents=True, exist_ok=True)
    run.selection_stamp.write_text(stamp + "\n")
    return _read_csv(run.selection_csv), json.loads(run.selection_json.read_text(encoding="utf-8"))


def parse_args(argv: Optional[list[str]] = None):
    d = SampleConfig()
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--select", "--dry-run", dest="select", action="store_true",
                    help="choose the sample from --list and write selection.csv/.json; "
                         "no key, no downloads")
    ap.add_argument("--list", help="AndroZoo latest_with-added-date.csv(.gz), for --select only")
    ap.add_argument("--replace-selection", action="store_true",
                    help="with --select: overwrite an existing selection")
    ap.add_argument("--check", action="store_true",
                    help="only validate the three files in --out before committing them")
    ap.add_argument("--out", default=str(ROOT / "ml" / "data" / "androzoo"))
    ap.add_argument("--work-dir", default=str(Path.home() / "apkookies-androzoo-work"),
                    help="resumable state + temporary APKs (outside the repo)")
    ap.add_argument("--per-class", type=int, default=d.per_class)
    ap.add_argument("--max-apk-mb", type=float, default=d.max_apk_mb)
    ap.add_argument("--since", default=d.since)
    ap.add_argument("--until", default=d.until)
    ap.add_argument("--benign-max-detections", type=int, default=d.benign_max_detections)
    ap.add_argument("--malicious-min-detections", type=int, default=d.malicious_min_detections)
    ap.add_argument("--min-scan-gap-days", type=int, default=d.min_scan_gap_days,
                    help="prefer APKs whose VirusTotal scan is this many days after `added`")
    ap.add_argument("--seed", type=int, default=d.seed)
    ap.add_argument("--concurrency", type=int, default=MAX_CONCURRENT_DOWNLOADS)
    ap.add_argument("--extract-workers", type=int, default=max(1, min(8, (os.cpu_count() or 2) - 1)))
    ap.add_argument("--temp-budget-gb", type=float, default=2.0)
    ap.add_argument("--timeout", type=int, default=300, help="seconds per APK analysis")
    ap.add_argument("--retry-failed", action="store_true")
    return ap.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    args = parse_args(argv)
    if args.check:
        problems = check_outputs(Path(args.out))
        print("OK to commit." if not problems else "NOT OK to commit:\n  " + "\n  ".join(problems))
        return 1 if problems else 0
    run = Run(work=Path(args.work_dir).expanduser(), out=Path(args.out))
    if args.select:
        summary = select(run, args)
        print(json.dumps({k: summary[k] for k in ("selected", "shortfall_per_class", "excluded",
                                                  "eligible_apks_per_class", "candidates_per_class",
                                                  "per_year", "stores", "label_maturity", "added_range",
                                                  "apk_mb", "malicious_markets", "play_only_malicious")},
                         indent=2, sort_keys=True))
        print(f"Selection written to {run.out.name}/selection.csv and selection.json; nothing downloaded.")
        return 0
    if args.list:
        raise SystemExit("--list is only used with --select: a run downloads the committed selection.csv")
    rows, summary = load_selection(run)
    download_and_extract(run, rows, concurrency=args.concurrency,
                         extract_workers=args.extract_workers,
                         temp_budget_gb=args.temp_budget_gb, timeout=args.timeout,
                         retry_failed=args.retry_failed)
    desc = finalize(run, rows, summary, args)
    print(f"Wrote features.jsonl.gz, samples.csv, DATASET.md to {run.out}. "
          f"Extracted OK: {desc['extracted_ok']}; pending: {desc['pending']}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
