"""Qualitative context-awareness demo for the presentation.

Scores the SAME permission set under different declared app categories via
the real, unmodified score_static() public API. Does not train or touch any
model artifact -- it only loads what's already in ml/models/.

Run from the repo root:
    python scripts/context_demo.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.scoring.risk_score import score_static
from backend.static_analysis import StaticBundle
from backend.static_analysis.manifest import ManifestFacts
from backend.static_analysis.structural import StructuralReport, SigningInfo
from backend.static_analysis.code_intel import CodeIntelReport
from backend.static_analysis.api_usage import ApiUsageReport
from backend.static_analysis.ioc_extraction import IOCReport
from backend.static_analysis.anti_analysis import AntiAnalysisReport


def make_bundle(category: str | None, permissions: list[str]) -> StaticBundle:
    manifest = ManifestFacts(permissions=permissions, declared_category=category)
    structural = StructuralReport(manifest=manifest, signing=SigningInfo())
    return StaticBundle(structural, CodeIntelReport(), ApiUsageReport([]), IOCReport([]), AntiAnalysisReport())


# Each scenario: (label, category, permissions). Same permission set is reused
# across contrasting categories on purpose -- that contrast IS the demo.
SCENARIOS = [
    ("SMS read/receive + Internet -- Communication app", "Communication",
     ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.INTERNET"]),
    ("SMS read/receive + Internet -- Banking app (same permissions)", "Banking",
     ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.INTERNET"]),
    ("Overlay permission -- Productivity app", "Productivity",
     ["android.permission.SYSTEM_ALERT_WINDOW"]),
    ("Overlay permission -- Banking app (same permission)", "Banking",
     ["android.permission.SYSTEM_ALERT_WINDOW"]),
    ("Camera+Mic+Location -- SocialMedia app", "SocialMedia",
     ["android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION"]),
    ("Camera+Mic+Location -- Wallpaper app (same permissions)", "Wallpaper",
     ["android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION"]),
]


def main():
    print(f"{'Scenario':60s} {'score':>7s} {'severity':>9s} {'verdict':>11s}  capabilities/context")
    print("-" * 130)
    for label, category, perms in SCENARIOS:
        result = score_static(make_bundle(category, perms))
        caps = ", ".join(result.capabilities) or "-"
        print(f"{label:60s} {result.score:7.3f} {result.severity:>9s} {result.verdict_label:>11s}  {caps}")
        for factor in result.contributing_factors:
            print(f"    - {factor}")
        print()


if __name__ == "__main__":
    main()