"""Measure the live scoring pipeline on a labelled APK test set.

Runs the same code path the API uses for a verdict -- static_analysis.run(path)
-> score_static(bundle) -- on every APK listed in a labels CSV, then reports
accuracy at the thresholds in config/thresholds.yaml. No sandbox, no network.

The APKs themselves never enter this repo (they live on the Windows analysis PC).
Only hashes, labels and scores are written out, so the results can be committed.

Labels CSV (UTF-8, header required; paths relative to the CSV's folder):

    path,label,group
    benign/bank_x.apk,benign,indian_bank
    malware/flubot_1.apk,malicious,banking_trojan

  label: benign | malicious      group: free text, reported separately (optional)

Run from the repo root:
    python ml/eval/evaluate_testset.py D:/apk-testset/labels.csv --policy default
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

LABELS = ("benign", "malicious")


@dataclass
class SampleResult:
    sha256: str
    label: str
    group: str
    score: float | None
    severity: str | None
    action: str | None
    seconds: float
    error: str | None = None
    verdict: str | None = None


def action_for(score: float, policy: dict) -> str:
    """Map a score to allow/warn/block using a response_policy band."""
    if score < policy["allow_below"]:
        return "allow"
    if score < policy["block_at_or_above"]:
        return "warn"
    return "block"


def binary_metrics(labels: list[str], predicted_positive: list[bool]) -> dict:
    """Confusion matrix + precision/recall/F1/FPR with 'malicious' as positive."""
    tp = sum(1 for y, p in zip(labels, predicted_positive) if y == "malicious" and p)
    fp = sum(1 for y, p in zip(labels, predicted_positive) if y == "benign" and p)
    fn = sum(1 for y, p in zip(labels, predicted_positive) if y == "malicious" and not p)
    tn = sum(1 for y, p in zip(labels, predicted_positive) if y == "benign" and not p)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and precision + recall else None)
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "accuracy": (tp + tn) / len(labels) if labels else None,
    }


def summarize(results: list[SampleResult]) -> dict:
    """Metrics over successfully scored samples, overall and per group."""
    scored = [r for r in results if r.score is not None]
    labels = [r.label for r in scored]
    summary: dict = {
        "n_listed": len(results),
        "n_scored": len(scored),
        "n_errors": len(results) - len(scored),
        "class_counts": {lab: labels.count(lab) for lab in LABELS},
        # Two operating points: only "block" counts as a detection, or warn+block.
        "block_as_positive": binary_metrics(labels, [r.action == "block" for r in scored]),
        "warn_or_block_as_positive": binary_metrics(
            labels, [r.action in ("warn", "block") for r in scored]),
    }
    if len(set(labels)) == 2:
        from sklearn.metrics import average_precision_score, roc_auc_score

        y = [1 if lab == "malicious" else 0 for lab in labels]
        s = [r.score for r in scored]
        summary["roc_auc"] = roc_auc_score(y, s)
        summary["pr_auc"] = average_precision_score(y, s)
    groups = sorted({r.group for r in scored if r.group})
    summary["per_group"] = {
        g: {
            "n": sum(1 for r in scored if r.group == g),
            "actions": {a: sum(1 for r in scored if r.group == g and r.action == a)
                        for a in ("allow", "warn", "block")},
        }
        for g in groups
    }
    return summary


def read_labels(csv_path: Path) -> list[tuple[Path, str, str]]:
    rows = []
    with csv_path.open(newline="", encoding="utf-8") as fh:
        for i, row in enumerate(csv.DictReader(fh), start=2):
            label = (row.get("label") or "").strip().lower()
            if label not in LABELS:
                raise SystemExit(f"{csv_path}:{i}: label must be one of {LABELS}, got {label!r}")
            rows.append((csv_path.parent / row["path"].strip(), label,
                         (row.get("group") or "").strip()))
    return rows


def evaluate(csv_path: Path, policy_name: str, mode: str | None = None) -> tuple[list[SampleResult], dict]:
    from backend.ingestion.file_signature import ContentKind, detect_bytes
    from backend.scoring.risk_score import score_static, thresholds
    from backend.static_analysis import run as run_static

    policy = thresholds()["response_policy"][policy_name]
    results = []
    for path, label, group in read_labels(csv_path):
        t0 = time.time()
        try:
            data = path.read_bytes()
        except OSError as e:
            # Exception text includes the file path; results get committed, so keep only the type.
            results.append(SampleResult("", label, group, None, None, None, 0.0,
                                        f"read: {type(e).__name__}"))
            continue
        sha256 = hashlib.sha256(data).hexdigest()
        if detect_bytes(data) != ContentKind.apk:  # same gate as the API pipeline
            results.append(SampleResult(sha256, label, group, None, None, None,
                                        time.time() - t0, "not an APK"))
            continue
        try:
            risk = score_static(run_static(path), mode=mode)
            results.append(SampleResult(sha256, label, group, risk.score, risk.severity,
                                        action_for(risk.score, policy), time.time() - t0,
                                        verdict=risk.verdict_label))
        except Exception as e:  # noqa: BLE001 - one bad APK must not stop the run
            # Type only: messages can embed temp paths or file names.
            results.append(SampleResult(sha256, label, group, None, None, None,
                                        time.time() - t0, f"analysis: {type(e).__name__}"))
    return results, policy


def run_info() -> dict:
    """What produced these numbers: lets stale results be recognised after code/model changes."""
    import datetime as dt
    import platform
    import subprocess
    from importlib import metadata

    from backend.hashing import fuzzy_hash
    from backend.static_analysis import quark_rules

    def version(pkg: str) -> str | None:
        try:
            return metadata.version(pkg)
        except metadata.PackageNotFoundError:
            return None

    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                text=True, timeout=10).stdout.strip() or None
        dirty = bool(subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"],
                                    cwd=ROOT, capture_output=True, text=True, timeout=10).stdout.strip())
    except (OSError, subprocess.SubprocessError):
        commit, dirty = None, None
    quark = quark_rules.analyze(ROOT / "tests" / "fixtures" / "dex" / "benign.dex").status
    return {
        "date_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "git_commit": commit,
        "git_dirty": dirty,
        "python": platform.python_version(),
        "os": platform.platform(terse=True),
        "androguard": version("androguard"),
        "py_tlsh": version("py-tlsh"),
        "fuzzy_status": fuzzy_hash.status().status,
        "quark": quark,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("labels_csv", type=Path)
    ap.add_argument("--policy", default="default",
                    help="response_policy band in config/thresholds.yaml")
    ap.add_argument("--out", type=Path, default=ROOT / "ml" / "results" / "testset")
    ap.add_argument("--scoring-mode", choices=["rules", "model", "retrained"], default=None,
                    help="default: the configured mode (config/thresholds.yaml scoring_mode)")
    args = ap.parse_args()

    from backend.scoring import modes
    mode = args.scoring_mode or modes.current_mode()
    results, policy = evaluate(args.labels_csv, args.policy, mode)
    summary = summarize(results)
    summary["policy"] = {"name": args.policy, **policy}
    summary["run_info"] = {**run_info(), "scoring_mode": mode}

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "metrics.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    with (args.out / "per_sample.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["sha256", "label", "group", "score", "severity", "action",
                         "verdict", "seconds", "error"])
        for r in results:
            writer.writerow([r.sha256, r.label, r.group, r.score, r.severity, r.action,
                             r.verdict or "", f"{r.seconds:.2f}", r.error or ""])
    print(json.dumps({k: summary[k] for k in ("n_scored", "n_errors", "class_counts",
                                              "block_as_positive")}, indent=2))
    print(f"Wrote {args.out / 'metrics.json'} and {args.out / 'per_sample.csv'}")


if __name__ == "__main__":
    main()
