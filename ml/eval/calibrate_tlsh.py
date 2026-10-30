"""Calibrate the look-alike (fuzzy) threshold from the APK test set.

A look-alike inherits a MALICIOUS verdict when its DEX TLSH distance to a known
malicious sample is small enough (config/thresholds.yaml:
verdict_inheritance_similarity + tlsh_max_distance; today distance <= 30, a
placeholder). This script measures, on real APKs, what "small enough" should be:

  * same-family pairs (two malicious samples of one family): these SHOULD match;
  * malicious <-> benign pairs: these must NEVER match (a genuine app would be
    flagged because it resembles malware; e.g. a trojan built on a bank's code);
  * malicious pairs of different families: matching them gives a malicious
    verdict anyway, but a wrong family label; reported, not optimised.

Pairs whose DEX is byte-identical are caught by the DEX-content tier and are left
out of the fuzzy statistics.

It suggests the largest distance that keeps a safety margin below the closest
malicious <-> benign pair, and reports same-family recall at the current and the
suggested distance. It does NOT change config: a person decides.

Runs where the APKs are (an isolated machine), on the same labels.csv as
evaluate_testset.py. An optional `family` column groups malicious samples into
families; without it, `group` is used (coarser: e.g. all "banking_trojan").

    python ml\\eval\\calibrate_tlsh.py D:\\apk-testset\\labels.csv
Output: ml/results/testset/tlsh_calibration.json (counts and distances only:
no file paths, no hashes).
"""
from __future__ import annotations

import argparse
import csv
import itertools
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SAFETY_MARGIN = 10          # TLSH distance units kept below the closest malicious<->benign pair


def read_samples(labels_csv: Path) -> list[dict]:
    from ml.eval.evaluate_testset import read_labels

    families = {}
    with labels_csv.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            families[(row.get("path") or "").strip()] = (row.get("family") or "").strip()
    out = []
    for path, label, group in read_labels(labels_csv):
        rel = str(path.relative_to(labels_csv.parent)) if path.is_relative_to(labels_csv.parent) else ""
        out.append({"path": path, "label": label,
                    "family": families.get(rel) or families.get(rel.replace("\\", "/")) or group})
    return out


def dex_hashes(samples: list[dict]) -> list[dict]:
    from backend.hashing.content_hash import content_hashes

    rows = []
    for s in samples:
        try:
            c = content_hashes(s["path"])
        except Exception as e:  # noqa: BLE001 - one unreadable APK must not stop the run
            rows.append({**s, "error": type(e).__name__})
            continue
        rows.append({**s, "dex_sha256": c.dex_sha256, "dex_tlsh": c.dex_tlsh})
    return rows


def _quantiles(values: list[int]) -> dict:
    if not values:
        return {"n": 0}
    v = sorted(values)
    q = lambda p: v[min(len(v) - 1, int(p * (len(v) - 1)))]   # noqa: E731
    return {"n": len(v), "min": v[0], "p10": q(.1), "median": statistics.median(v), "p90": q(.9),
            "max": v[-1]}


def calibrate(rows: list[dict], current_max: int) -> dict:
    from backend.hashing.fuzzy_hash import tlsh_distance

    usable = [r for r in rows if r.get("dex_tlsh")]
    same_family, mal_benign, cross_family, identical = [], [], [], 0
    for a, b in itertools.combinations(usable, 2):
        if a["label"] == "benign" and b["label"] == "benign":
            continue
        if a["dex_sha256"] and a["dex_sha256"] == b["dex_sha256"]:
            identical += 1
            continue
        d = tlsh_distance(a["dex_tlsh"], b["dex_tlsh"])
        if a["label"] != b["label"]:
            mal_benign.append(d)
        elif a["family"] and a["family"] == b["family"]:
            same_family.append(d)
        else:
            cross_family.append(d)

    closest_benign = min(mal_benign) if mal_benign else None
    suggested = None if closest_benign is None else max(0, closest_benign - SAFETY_MARGIN)

    def recall(limit):
        return None if limit is None or not same_family else round(
            sum(1 for d in same_family if d <= limit) / len(same_family), 3)

    def count(values, limit):
        return None if limit is None else sum(1 for d in values if d <= limit)

    return {
        "samples": {"total": len(rows), "with_dex_tlsh": len(usable),
                    "unreadable": sum(1 for r in rows if r.get("error")),
                    "malicious": sum(1 for r in usable if r["label"] == "malicious"),
                    "benign": sum(1 for r in usable if r["label"] == "benign"),
                    "families": len({r["family"] for r in usable if r["label"] == "malicious"})},
        "pairs_with_identical_dex": identical,
        "distances": {"same_family": _quantiles(same_family),
                      "malicious_benign": _quantiles(mal_benign),
                      "malicious_cross_family": _quantiles(cross_family)},
        "current_max_distance": current_max,
        "at_current": {"same_family_recall": recall(current_max),
                       "malicious_benign_matches": count(mal_benign, current_max),
                       "cross_family_matches": count(cross_family, current_max)},
        "suggested_max_distance": suggested,
        "suggestion_rule": f"closest malicious<->benign distance minus a margin of {SAFETY_MARGIN}",
        "at_suggested": {"same_family_recall": recall(suggested),
                         "malicious_benign_matches": count(mal_benign, suggested),
                         "cross_family_matches": count(cross_family, suggested)},
        "note": "Advisory only: config/thresholds.yaml is not changed. Few pairs = weak evidence.",
    }


def config_for(max_distance: int, tlsh_max: int) -> float:
    """The verdict_inheritance_similarity that makes `max_distance` the matching limit."""
    return round(1 - max_distance / tlsh_max, 4)


def main(argv=None) -> int:
    from config import thresholds

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("labels_csv", type=Path)
    ap.add_argument("--out", type=Path, default=ROOT / "ml" / "results" / "testset")
    args = ap.parse_args(argv)

    t = thresholds()
    tlsh_max = int(t["tlsh_max_distance"])
    current_max = round(tlsh_max * (1 - float(t["verdict_inheritance_similarity"])))
    result = calibrate(dex_hashes(read_samples(args.labels_csv)), current_max)
    if result["suggested_max_distance"] is not None:
        result["suggested_config"] = {
            "verdict_inheritance_similarity": config_for(result["suggested_max_distance"], tlsh_max),
            "tlsh_max_distance": tlsh_max}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "tlsh_calibration.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
