"""Static analysis orchestration — runs the sub-passes and returns a bundle.

Order: structural (manifest+signing+inventory) -> code intel (strings+obfuscation)
-> api usage (context) -> IOC extraction -> anti-analysis. Downstream scoring
consumes `StaticBundle`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from backend.static_analysis import (
    anti_analysis,
    api_usage,
    category as category_mod,
    code_intel,
    dex_analysis,
    ioc_extraction,
    quark_rules,
    structural,
)


@dataclass
class StaticBundle:
    structural: structural.StructuralReport
    code_intel: code_intel.CodeIntelReport
    api_usage: api_usage.ApiUsageReport
    iocs: ioc_extraction.IOCReport
    anti_analysis: anti_analysis.AntiAnalysisReport
    quark: quark_rules.QuarkReport = field(default_factory=quark_rules.QuarkReport)
    analysis_status: dict = field(default_factory=dict)
    coverage: float = 1.0
    # Resolved once here and reused by scoring and training (static_analysis/category.py).
    category: str | None = None
    category_source: str | None = None    # declared | inferred | none; None = not resolved


# Every stage reports a status so "found nothing" and "couldn't look" never look alike:
#   observed   ran and collected evidence
#   heuristic  ran, but with a pattern/heuristic method (weaker evidence)
#   unavailable a tool/dependency/input was missing, so it didn't run
#   failed     it ran and errored (e.g. manifest unreadable)
#   disabled   optional stage switched off (e.g. Quark not configured)


def manifest_parsed(manifest) -> bool:
    """A manifest we couldn't read yields no package name."""
    return bool(manifest.package_name)


def run(path: str | Path) -> StaticBundle:
    struct = structural.analyze(path)
    dex = dex_analysis.build(path, target_sdk=struct.manifest.target_sdk)
    ci = code_intel.analyze(path, dex_entries=dex.dex_entries)
    # The same category drives API suspicion here and the rules/KG in scoring.
    category, category_source = category_mod.resolve_category(
        struct.manifest.declared_category, struct.manifest.package_name, ci.dex_strings)
    apis = api_usage.analyze(dex, category, struct.manifest)
    iocs = ioc_extraction.extract(ci.dex_strings)
    anti = anti_analysis.analyze(dex, struct.manifest)
    quark = quark_rules.analyze(path)
    manifest_heuristic = struct.manifest.parser == "raw_fallback"
    if not manifest_parsed(struct.manifest):
        manifest_status = {
            "status": "failed",
            "reason": "AndroidManifest.xml could not be parsed (no package name): the file is "
                      "malformed, not an APK, or deliberately breaks parsers.",
        }
    elif manifest_heuristic:
        manifest_status = {"status": "heuristic",
                           "reason": "Raw permission scan used; component metadata may be incomplete."}
    else:
        manifest_status = {"status": "observed", "reason": "Binary manifest parsed."}
    status = {
        "manifest": manifest_status,
        "structural": {
            "status": "observed" if struct.signing.certificates else "unavailable",
            "reason": "Archive inventory and signing certificates collected." if struct.signing.certificates
                      else "No signing certificate could be read (unsigned or unreadable signing block).",
        },
        "code_intel": {
            "status": "heuristic",
            "reason": "Obfuscation/packer signals are byte-marker and entropy heuristics; "
                      "call-graph taint analysis is not implemented.",
        },
        "api_usage": {"status": apis.status, "reason": apis.reason},
        "iocs": {
            "status": "heuristic",
            "reason": "IOC extraction is pattern-based.",
        },
        "anti_analysis": {"status": anti.status, "reason": anti.reason},
        "quark": {"status": quark.status, "reason": quark.reason},
        "category": {
            "status": {"declared": "observed", "inferred": "heuristic", "none": "unavailable"}[category_source],
            "reason": {"declared": "Category declared in the manifest.",
                       "inferred": "Category guessed from package name / code strings (keyword match).",
                       "none": "No category declared or inferred; category-dependent checks are off."}[category_source],
        },
    }
    return StaticBundle(
        structural=struct, code_intel=ci, api_usage=apis, iocs=iocs, anti_analysis=anti,
        quark=quark,
        analysis_status=status, coverage=0.55 if manifest_heuristic else 0.75,
        category=category, category_source=category_source,
    )
