"""End-to-end demo: run the REAL static-analysis + scoring pipeline on actual
APK files (not synthetic ManifestFacts like scripts/context_demo.py).

This is the "give a demo on a real sample" version: it calls the same public
functions the orchestrator (backend/orchestration/pipeline.py) calls --
static_analysis.run(path) -> score_static(bundle) -- just without the
hashing/sandbox/report-persistence plumbing around them, so it's a good
narrow slice to present just the ML/scoring half of the project.

Run from the repo root:
    python scripts/analyze_apk_demo.py path/to/app.apk [more.apk ...]
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.static_analysis import run as run_static
from backend.scoring.risk_score import score_static


def analyze_one(path: Path) -> None:
    print(f"\n=== {path.name} ===")
    t0 = time.time()
    bundle = run_static(path)
    t1 = time.time()
    result = score_static(bundle)
    t2 = time.time()

    m = bundle.structural.manifest
    print(f"  package          : {m.package_name}")
    print(f"  declared/inferred category : {result.category or m.declared_category}")
    print(f"  permissions      : {len(m.permissions)} total")
    print(f"  score            : {result.score:.3f}")
    print(f"  severity         : {result.severity}")
    print(f"  verdict          : {result.verdict_label}")
    print(f"  needs sandbox?   : {result.needs_dynamic_analysis}")
    caps = ", ".join(result.capabilities) or "-"
    print(f"  capabilities     : {caps}")
    if result.rules_triggered:
        print("  rules triggered  :")
        for rule in result.rules_triggered:
            print(f"    - {rule}")
    print("  contributing factors:")
    for factor in result.contributing_factors:
        print(f"    - {factor}")
    print(f"  timing           : static={t1 - t0:.2f}s  scoring={t2 - t1:.2f}s")


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    for arg in sys.argv[1:]:
        analyze_one(Path(arg))


if __name__ == "__main__":
    main()