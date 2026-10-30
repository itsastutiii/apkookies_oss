"""How often do the permission-based rules and knowledge-graph edges fire on BENIGN apps?

A rule that fires on more than ~1% of benign apps can't be a hard override (it
would block one genuine app in a hundred): see scoring/rules_engine.py.

Two sources:
  * --cicmaldroid: CICMalDroid 2020's permission matrix (the npz written by
    ml/training/prepare_cicmaldroid.py; 1,795 benign and 9,803 malicious apps,
    permissions only). Measures stage-1 (permission) evidence: rules are run
    through the real rules engine on bundles holding only the permissions, once
    with no category and once as if every app were a Banking app (the worst
    case for bank apps); knowledge-graph capabilities are derived by the real
    knowledge graph.
  * --testset: any labelled APK set (the labels.csv of docs/TESTSET.md). Runs the
    full static analysis, so every rule at every stage is measured. Run it where
    the APKs are (an isolated machine).

Output: ml/results/benign_firing_rates.json (+ .md): rates only, no app names,
hashes or paths.

    python ml/eval/benign_firing_rates.py --cicmaldroid ml/data/cicmaldroid_permissions.npz
    python ml\\eval\\benign_firing_rates.py --testset D:\\apk-testset\\labels.csv
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

HARD_OVERRIDE_MAX_BENIGN_RATE = 0.01
CATEGORY_CASES = (None, "Banking")


def _permission_bundle(permissions: list[str], category: str | None):
    from backend.static_analysis import StaticBundle
    from backend.static_analysis.anti_analysis import AntiAnalysisReport
    from backend.static_analysis.api_usage import ApiUsageReport
    from backend.static_analysis.code_intel import CodeIntelReport
    from backend.static_analysis.ioc_extraction import IOCReport
    from backend.static_analysis.manifest import ManifestFacts
    from backend.static_analysis.structural import SigningInfo, StructuralReport

    m = ManifestFacts(package_name="x", permissions=permissions, declared_category=category)
    return StaticBundle(StructuralReport(manifest=m, signing=SigningInfo()), CodeIntelReport(),
                        ApiUsageReport(), IOCReport(), AntiAnalysisReport())


def _rates(counter: Counter, n: int) -> dict:
    return {k: {"apps": v, "rate": round(v / n, 4)} for k, v in sorted(counter.items())} if n else {}


def measure_permission_rows(rows: list[tuple[list[str], str]]) -> dict:
    """rows: (permissions, label) with label 'benign' | 'malicious'."""
    from backend.scoring import rules_engine
    from backend.scoring.features import SENSITIVE_PERMISSIONS
    from backend.scoring.knowledge_graph import default_graph

    kg = default_graph()
    caps_spec = kg._caps
    n = Counter(label for _, label in rows)
    fired = {lab: {str(c): Counter() for c in CATEGORY_CASES} for lab in n}
    caps = {lab: Counter() for lab in n}
    sensitive = {lab: Counter() for lab in n}
    for perms, label in rows:
        for cat in CATEGORY_CASES:
            for h in rules_engine.evaluate(_permission_bundle(perms, cat), cat):
                fired[label][str(cat)][h.rule_id] += 1
        for c in kg.derive_capabilities(perms, None):
            caps[label][c.capability] += 1
        k = sum(1 for p in perms if p in SENSITIVE_PERMISSIONS)
        for threshold in (1, 3):
            if k >= threshold:
                sensitive[label][f">={threshold} sensitive permissions"] += 1

    def edges():
        out = {}
        for cap, spec in caps_spec.items():
            for edge in ("anomalous_for", "normal_for"):
                for entry in spec.get(edge) or []:
                    cat = entry["category"] if isinstance(entry, dict) else entry
                    src = entry.get("source") if isinstance(entry, dict) else None
                    out[f"{cap} {edge.upper()} {cat}"] = {
                        "benign_rate_if_in_category": round(caps["benign"][cap] / n["benign"], 4)
                        if n.get("benign") else None,
                        "source": src}
        return out

    result = {
        "n": dict(n),
        "rules": {lab: {cat: _rates(c, n[lab]) for cat, c in fired[lab].items()} for lab in n},
        "kg_capabilities": {lab: _rates(caps[lab], n[lab]) for lab in n},
        "kg_edges": edges(),
        "transparent_sensitive_permissions": {lab: _rates(sensitive[lab], n[lab]) for lab in n},
    }
    result["hard_override_check"] = check_hard_rules(result)
    return result


def check_hard_rules(result: dict) -> dict:
    """Every hard-override rule must fire on < 1% of benign apps in every category case."""
    from backend.scoring import rules_engine

    out = {}
    for cat, rates in (result.get("rules", {}).get("benign") or {}).items():
        for rule_id, r in rates.items():
            hard = rule_id in rules_engine.HARD_RULES
            out[f"{rule_id} (category {cat})"] = {
                "benign_rate": r["rate"], "hard_override": hard,
                "allowed": (not hard) or r["rate"] < HARD_OVERRIDE_MAX_BENIGN_RATE}
    return out


def load_cicmaldroid(path: Path) -> list[tuple[list[str], str]]:
    import numpy as np

    d = np.load(path, allow_pickle=True)
    vocab = [str(v) for v in d["vocabulary"]]
    rows = []
    for x, lab in zip(d["X"], d["labels"]):
        perms = [vocab[i] for i in np.flatnonzero(x)]
        rows.append((perms, "benign" if str(lab).upper() == "BENIGN" else "malicious"))
    return rows


def measure_testset(labels_csv: Path) -> dict:
    """Full static analysis of each APK; every rule at its reached stage."""
    from backend.scoring import rules_engine
    from backend.static_analysis import run as run_static
    from ml.eval.evaluate_testset import read_labels

    n, fired, errors = Counter(), {}, 0
    for path, label, _group in read_labels(labels_csv):
        try:
            hits = rules_engine.evaluate(run_static(path))
        except Exception:  # noqa: BLE001 - one bad APK must not stop the run
            errors += 1
            continue
        n[label] += 1
        c = fired.setdefault(label, Counter())
        for h in hits:
            c[h.rule_id] += 1
            if h.stage:
                c[f"{h.rule_id} stage {h.stage}"] += 1
    result = {"n": dict(n), "errors": errors,
              "rules": {lab: {"detected": _rates(c, n[lab])} for lab, c in fired.items()}}
    result["hard_override_check"] = check_hard_rules(result)
    return result


def to_markdown(result: dict, title: str) -> str:
    lines = [f"# {title}", "", f"Apps: {result['n']}. A hard-override rule must fire on "
             f"< {HARD_OVERRIDE_MAX_BENIGN_RATE:.0%} of benign apps.", ""]
    for cat, rates in (result.get("rules", {}).get("benign") or {}).items():
        mal = result["rules"].get("malicious", {}).get(cat, {})
        lines += [f"## Rules (category: {cat})", "", "| rule | benign | malicious |", "|---|---|---|"]
        for rid, r in rates.items():
            m = mal.get(rid, {}).get("rate")
            lines.append(f"| {rid} | {r['rate']:.1%} | {'' if m is None else f'{m:.1%}'} |")
        lines.append("")
    if "kg_edges" in result:
        lines += ["## Knowledge-graph edges (fires for every app of that category that has the capability)",
                  "", "| edge | benign rate if the app is in that category | source |", "|---|---|---|"]
        for edge, e in result["kg_edges"].items():
            lines.append(f"| {edge} | {e['benign_rate_if_in_category']:.1%} | {e['source'] or 'none'} |")
        lines.append("")
    bad = [k for k, v in result.get("hard_override_check", {}).items() if not v["allowed"]]
    lines += ["## Hard-override check", "", "Violations: " + (", ".join(bad) if bad else "none"), ""]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cicmaldroid", type=Path)
    ap.add_argument("--testset", type=Path)
    ap.add_argument("--out", type=Path, default=ROOT / "ml" / "results")
    args = ap.parse_args(argv)
    if not (args.cicmaldroid or args.testset):
        ap.error("give --cicmaldroid and/or --testset")
    args.out.mkdir(parents=True, exist_ok=True)
    if args.cicmaldroid:
        r = measure_permission_rows(load_cicmaldroid(args.cicmaldroid))
        r["source"] = "CICMalDroid 2020 permission matrix (permissions only; stage-1 evidence)"
        (args.out / "benign_firing_rates.json").write_text(json.dumps(r, indent=2), encoding="utf-8")
        (args.out / "benign_firing_rates.md").write_text(
            to_markdown(r, "Benign firing rates: CICMalDroid 2020 (permissions only)"), encoding="utf-8")
        print(to_markdown(r, "CICMalDroid 2020"))
    if args.testset:
        r = measure_testset(args.testset)
        out = args.out / "testset"
        out.mkdir(parents=True, exist_ok=True)
        (out / "benign_firing_rates.json").write_text(json.dumps(r, indent=2), encoding="utf-8")
        print(json.dumps(r, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
