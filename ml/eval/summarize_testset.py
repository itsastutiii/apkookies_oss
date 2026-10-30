"""Check and summarise test-set results before sharing them.

Input: the folder written by evaluate_testset.py (metrics.json + per_sample.csv),
committed back to the repo. This script:
  1. validates them (expected fields, 64-hex hashes, valid labels) and refuses
     anything that looks like a file path or phone number, which must never be
     committed;
  2. writes SUMMARY.md next to them: accuracy at both operating points, the
     misses (malicious allowed) and false alarms (benign blocked) by hash, errors,
     and which code/environment produced the run.

    python ml/eval/summarize_testset.py                      # ml/results/testset
    python ml/eval/summarize_testset.py path/to/results_dir
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COLUMNS = ["sha256", "label", "group", "score", "severity", "action", "verdict", "seconds", "error"]
_PATH_LIKE = re.compile(r"[A-Za-z]:\\|/Users/|/home/|\\\\")
_PHONE_LIKE = re.compile(r"\b\d{10,13}\b")


class ResultsError(ValueError):
    pass


def load(results_dir: Path) -> tuple[dict, list[dict]]:
    metrics = json.loads((results_dir / "metrics.json").read_text(encoding="utf-8"))
    with (results_dir / "per_sample.csv").open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    return metrics, rows


def validate(metrics: dict, rows: list[dict]) -> list[str]:
    """Return problems found; a non-empty list means don't commit as-is."""
    problems = []
    for key in ("n_listed", "n_scored", "class_counts", "block_as_positive",
                "warn_or_block_as_positive", "policy"):
        if key not in metrics:
            problems.append(f"metrics.json is missing '{key}'")
    if rows and list(rows[0].keys()) != COLUMNS:
        problems.append(f"per_sample.csv columns are {list(rows[0].keys())}, expected {COLUMNS}")
    for i, r in enumerate(rows, start=2):
        if r.get("sha256") and not re.fullmatch(r"[0-9a-f]{64}", r["sha256"]):
            problems.append(f"per_sample.csv:{i}: sha256 is not 64 lowercase hex")
        if r.get("label") not in ("benign", "malicious"):
            problems.append(f"per_sample.csv:{i}: label {r.get('label')!r}")
        for field in ("group", "error"):
            value = r.get(field) or ""
            if _PATH_LIKE.search(value):
                problems.append(f"per_sample.csv:{i}: {field} looks like a file path")
            if _PHONE_LIKE.search(value):
                problems.append(f"per_sample.csv:{i}: {field} contains a long number (phone?)")
    if len(rows) != metrics.get("n_listed", len(rows)):
        problems.append(f"per_sample.csv has {len(rows)} rows but metrics.json n_listed="
                        f"{metrics.get('n_listed')}")
    return problems


def _pct(x) -> str:
    return "n/a" if x is None else f"{100 * x:.1f}%"


def _op_table(m: dict) -> list[str]:
    out = ["| operating point | precision | recall | false-positive rate | TP | FP | FN | TN |",
           "|---|---|---|---|---|---|---|---|"]
    for key, name in (("block_as_positive", "only **block** = detection"),
                      ("warn_or_block_as_positive", "**warn or block** = detection")):
        b = m[key]
        out.append(f"| {name} | {_pct(b['precision'])} | {_pct(b['recall'])} | "
                   f"{_pct(b['false_positive_rate'])} | {b['tp']} | {b['fp']} | {b['fn']} | {b['tn']} |")
    return out


def render(metrics: dict, rows: list[dict]) -> str:
    info = metrics.get("run_info", {})
    misses = [r for r in rows if r["label"] == "malicious" and r["action"] == "allow"]
    false_alarms = [r for r in rows if r["label"] == "benign" and r["action"] == "block"]
    errors = [r for r in rows if r["error"]]
    lines = [
        "# APK test-set results",
        "",
        f"Scored {metrics['n_scored']} of {metrics['n_listed']} APKs "
        f"({metrics['class_counts'].get('malicious', 0)} malicious, "
        f"{metrics['class_counts'].get('benign', 0)} benign); {metrics.get('n_errors', 0)} errors. "
        f"Policy: `{metrics['policy'].get('name')}` (allow < {metrics['policy'].get('allow_below')}, "
        f"block ≥ {metrics['policy'].get('block_at_or_above')}).",
        "",
        *_op_table(metrics),
        "",
        f"ROC-AUC: {metrics.get('roc_auc', 'n/a')} · PR-AUC: {metrics.get('pr_auc', 'n/a')}",
        "",
        "## Produced by",
        "",
        *[f"- {k}: `{v}`" for k, v in info.items()],
        *([] if info else ["- (no run_info: produced by an older evaluate_testset.py)"]),
        "",
        "## Per group",
        "",
        "| group | n | allow | warn | block |",
        "|---|---|---|---|---|",
        *[f"| {g} | {v['n']} | {v['actions']['allow']} | {v['actions']['warn']} | {v['actions']['block']} |"
          for g, v in metrics.get("per_group", {}).items()],
        "",
        f"## Missed malware (malicious → allow): {len(misses)}",
        "",
        *[f"- `{r['sha256'][:16]}…` {r['group']} score={r['score']} verdict={r['verdict']}" for r in misses],
        "",
        f"## False alarms (benign → block): {len(false_alarms)}",
        "",
        *[f"- `{r['sha256'][:16]}…` {r['group']} score={r['score']}" for r in false_alarms],
        "",
        f"## Errors: {len(errors)}",
        "",
        *[f"- `{(r['sha256'] or '?')[:16]}` {r['group']}: {r['error']}" for r in errors],
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("results_dir", nargs="?", type=Path, default=ROOT / "ml" / "results" / "testset")
    args = ap.parse_args()
    metrics, rows = load(args.results_dir)
    problems = validate(metrics, rows)
    if problems:
        print("NOT OK to commit:\n  " + "\n  ".join(problems))
        raise SystemExit(1)
    out = args.results_dir / "SUMMARY.md"
    out.write_text(render(metrics, rows), encoding="utf-8")
    print(f"OK. Wrote {out}")


if __name__ == "__main__":
    main()
