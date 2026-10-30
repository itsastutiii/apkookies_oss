"""5-minute tour of what APKookies does. No APKs needed.

Uses only the committed test fixtures (tests/fixtures/dex/*.dex: tiny benign
DEX files compiled from source; never executed) and archives built in memory.
(The pipeline briefly writes the sample to .artifacts/ and wipes it, as in production.)

    python scripts/try_it_yourself.py           # the tour
    python scripts/try_it_yourself.py --json    # just the full report JSON from step 6
"""
from __future__ import annotations

import asyncio
import io
import logging
import os
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
# The tour never touches the real verdict database.
os.environ["VERDICT_DB_PATH"] = ":memory:"
logging.disable(logging.WARNING)  # keep the tour readable (androguard is chatty)
try:
    from loguru import logger as _loguru  # androguard logs through loguru
    _loguru.remove()
except ImportError:
    pass

FIX = ROOT / "tests" / "fixtures" / "dex"
BAD = (FIX / "suspicious.dex").read_bytes()
GOOD = (FIX / "benign.dex").read_bytes()
MANIFEST = b"\x03\x00\x08\x00" + b"\x00" * 64   # deliberately unreadable manifest


def zip_of(entries, stored=False, extra=b""):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)
        if extra:
            zf.writestr("META-INF/CERT.RSA", extra)
    return buf.getvalue()


def title(n, text):
    print(f"\n=== {n}. {text} ===")


def report_json() -> None:
    from backend.orchestration import pipeline
    from schemas.report import InputType

    a = zip_of([("AndroidManifest.xml", MANIFEST), ("classes.dex", BAD)])
    rep = asyncio.run(pipeline.analyze(InputType.apk, data=a, filename="demo.zip")).report
    print(rep.model_dump_json(indent=2))


def main() -> None:
    if "--json" in sys.argv:
        return report_json()
    from backend.hashing import exact_hash, fuzzy_hash
    from backend.hashing.content_hash import content_hashes
    from backend.hashing.lookup import HashLookupService
    from backend.static_analysis import anti_analysis, api_usage, dex_analysis, signing

    title(1, "Hashes that survive re-zipping")
    a = zip_of([("AndroidManifest.xml", MANIFEST), ("classes.dex", BAD)])
    b = zip_of([("classes.dex", BAD), ("AndroidManifest.xml", MANIFEST)], stored=True, extra=b"x")
    print("whole-APK SHA-256 equal?   ", exact_hash.hash_bytes(a).sha256 == exact_hash.hash_bytes(b).sha256)
    print("DEX-content SHA-256 equal? ", content_hashes(a).dex_sha256 == content_hashes(b).dex_sha256)
    st = fuzzy_hash.status()
    print("fuzzy hashing:", st.status, "-", st.note or "TLSH installed")

    title(2, "Similarity can only pass on 'malicious', never 'benign'")
    for verdict in ("malicious", "benign"):
        svc = HashLookupService()
        svc.record_verdict(exact_hash.hash_bytes(a).sha256, verdict, content_hashes(a))
        res = svc.lookup(exact_hash.hash_bytes(b), content_hashes(b))
        print(f"original stored as {verdict:9s} -> re-zipped copy gets:",
              res.verdict if res.hit else "nothing (full analysis runs)")

    title(3, "API use = real calls, not words in the file")
    bad_ix = dex_analysis.build(b"", dex_entries=[("classes.dex", BAD)])
    good_ix = dex_analysis.build(b"", dex_entries=[("classes.dex", GOOD)])
    for name, ix in (("suspicious.dex", bad_ix), ("benign.dex (has decoy text)", good_ix)):
        obs = api_usage.analyze(ix, app_category="banking").observations
        print(f"{name}: {', '.join(o.marker for o in obs) or '-'}")
    send = next(o for o in api_usage.analyze(bad_ix, "banking").observations if o.marker == "sms_send")
    print("  where SMS is sent from:", send.locations)

    title(4, "Evasion checks with their exact location")
    for f in anti_analysis.analyze(bad_ix).findings:
        weak = "  (also common in legit apps)" if f.common_in_benign else ""
        print(f"{f.technique:20s} {f.mitre_id:10s} {f.locations[0]}{weak}")
    print("benign.dex findings:", anti_analysis.analyze(good_ix).findings or "none")

    title(5, "Bank impersonation check (allowlist)")
    entries = ({"bank": "Demo Bank", "packages": {"com.demobank"}, "app_names": {"demobank"},
                "certs": {"aa" * 32}},)
    for pkg, label, cert in (("com.demobank", None, "aa" * 32), ("com.demobank", None, "bb" * 32),
                             ("com.other", "DemoBank", "bb" * 32)):
        r = signing.check_allowlist(pkg, label, [cert], entries=entries)
        rule = {"package": "R004 -> score floor 0.90 (block)",
                "app_name": "R004B -> score floor 0.40 (warn)"}.get(r.matched_by, "")
        print(f"{pkg:13s} {str(label):9s} cert {cert[:4]}…: {r.status:13s} {rule if r.status == 'impersonation' else ''}")

    title(6, "Full pipeline report (fixture DEX + unreadable manifest)")
    from backend.orchestration import pipeline
    from schemas.report import InputType
    rep = asyncio.run(pipeline.analyze(InputType.apk, data=a, filename="demo.zip")).report
    print("verdict:", rep.verdict.label.value, f"(score {rep.risk.score:.2f}) - never 'benign' when the manifest can't be read")
    print("stage status:", {k: v["status"] for k, v in rep.static_bundle["analysis_status"].items()})
    print("MITRE (ATT&CK Mobile", rep.mitre_attack[0].attack_version + "):")
    for m in rep.mitre_attack:
        print(f"  {m.technique_id:10s} {m.technique_name:45s} evidence={m.evidence_strength}")
    print("hashes.fuzzy_status:", rep.hashes.fuzzy_status, "| dex_sha256:", rep.hashes.dex_sha256[:16] + "…")
    print("verdict provenance:", {k: rep.verdict.provenance[k] for k in ("source", "scoring_version", "fingerprint")})

    phase_2a(a, b)
    look_alikes()
    print("\nDone. Full checks: python -m pytest -q")


def phase_2a(a: bytes, b: bytes) -> None:
    from backend.hashing import exact_hash
    from backend.hashing.content_hash import content_hashes
    from backend.hashing.lookup import HashLookupService
    from backend.hashing.verdict_store import VerdictStore
    from backend.scoring import rules_engine
    from backend.scoring.risk_score import score_static
    from backend.static_analysis import StaticBundle, run as run_static
    from backend.static_analysis.anti_analysis import AntiAnalysisReport
    from backend.api.dependencies import resolve_action
    from backend.static_analysis.api_usage import ApiCategory, ApiUsageObservation, ApiUsageReport
    from backend.static_analysis.category import resolve_category
    from config import thresholds
    from backend.static_analysis.code_intel import CodeIntelReport
    from backend.static_analysis.ioc_extraction import ExtractedIOC, IOCReport
    from backend.static_analysis.manifest import ManifestFacts
    from backend.static_analysis.structural import SigningInfo, StructuralReport

    title(7, "One app category; graded evidence: only stage 4-5 behaviour blocks")
    for pkg, strings in (("com.demo.bank", []), (None, ["content://sms/inbox"])):
        print(f"package={pkg!s:20s} strings={strings!s:24s} -> category {resolve_category(None, pkg, strings)}")
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "demo.zip"
        path.write_bytes(a)
        bundle = run_static(path)
    def show(label, bdl):
        r = score_static(bdl)
        rules = ", ".join(f"{h.rule_id}(stage {h.stage})" if h.stage else h.rule_id for h in r.rules_triggered)
        print(f"{label}: {rules or 'no rules'} -> score {r.score:.2f}, "
              f"{resolve_action(r.score, 'default')}{', sandbox' if r.needs_dynamic_analysis else ''}")
    show("suspicious.dex (accessibility + overlay + SMS code, no category)", bundle)
    from dataclasses import replace as _replace
    from backend.static_analysis.quark_rules import QuarkBehaviour, QuarkReport
    with_flow = _replace(bundle, quark=QuarkReport(status="observed", behaviours=[QuarkBehaviour(
        "demo.json", "Read SMS and send it over the network (data flow)", 100, 1.0, ["sms"])]))
    show("same + a stage-5 data-flow behaviour (Quark)", with_flow)
    pm = StaticBundle(StructuralReport(manifest=ManifestFacts(package_name="com.demo.passwords"),
                                       signing=SigningInfo()), CodeIntelReport(),
                      ApiUsageReport([ApiUsageObservation(ApiCategory.accessibility, "a11y", "autofill"),
                                      ApiUsageObservation(ApiCategory.overlay, "overlay", "autofill")]),
                      IOCReport(), AntiAnalysisReport())
    risk = score_static(pm)
    actions = {t: resolve_action(risk.score, t) for t in thresholds()["response_policy"]}
    print("accessibility + overlay only (password-manager-like): rules =",
          [h.rule_id for h in risk.rules_triggered], f"score {risk.score:.2f} ->", sorted(set(actions.values())),
          "| sandbox:", risk.needs_dynamic_analysis)

    title(8, "Score breakdown: every step that built the number")
    print("An app with no permissions but a hardcoded Telegram bot token (rule R003, floor 0.40 = warn + sandbox):")
    token = ExtractedIOC(type="telegram_token", value="123456789:" + "A" * 35)
    demo = StaticBundle(StructuralReport(manifest=ManifestFacts(package_name="com.demo.app"),
                                         signing=SigningInfo()),
                        CodeIntelReport(), ApiUsageReport(), IOCReport([token]), AntiAnalysisReport())
    risk = score_static(demo)
    for step in risk.breakdown:
        print(f"  {step.step:34s} {step.kind:5s} {step.delta:+.3f} -> {step.score_after:.3f}  {step.detail}")
    print(f"  final score {risk.score:.3f} = sum of the deltas")

    title(9, "Verdict lifecycle: persistence, analyst override, stale re-checks")
    sha = exact_hash.hash_bytes(a).sha256
    with tempfile.TemporaryDirectory() as d:
        db = Path(d) / "verdicts.sqlite3"
        HashLookupService(store=VerdictStore(db)).record_verdict(sha, "malicious", content_hashes(a))
        svc = HashLookupService(store=VerdictStore(db))           # "restart"
        print("after restart: same file ->", svc.lookup(exact_hash.hash_bytes(a)).verdict,
              "| re-zipped copy ->", svc.lookup(exact_hash.hash_bytes(b), content_hashes(b)).verdict)
        svc.override(sha, "benign", "demo-analyst", "false positive (demo)")
        print("analyst override to benign: same file ->", svc.lookup(exact_hash.hash_bytes(a)).verdict,
              "| re-zipped copy ->", svc.lookup(exact_hash.hash_bytes(b), content_hashes(b)).verdict or
              "nothing (benign never spreads)")
        print("audit log:", [(e["action"], e["actor"], e["old_verdict"], e["new_verdict"])
                             for e in svc.store.history(sha)])
        svc.clear(sha, "demo-analyst", "undo (demo)")
        svc.record_verdict(sha, "malicious", content_hashes(a))
        retrained = {**svc.store.current_provenance(), "fingerprint": "after-retraining"}
        after = HashLookupService(store=VerdictStore(db, current_provenance=retrained))
        res = after.lookup(exact_hash.hash_bytes(a), content_hashes(a))
        print("after retraining: known?", res.hit, "| stale verdict:", res.stale_verdict,
              "-> the file is re-analysed;", len(after.store.stale()), "stale verdict(s) waiting")


def look_alikes() -> None:
    """Section 10: how a known sample's look-alikes are caught (or not), tier by tier."""
    from backend.hashing import exact_hash, fuzzy_hash
    from backend.hashing.content_hash import content_hashes
    from backend.hashing.lookup import HashLookupService
    from backend.hashing.verdict_store import VerdictStore

    title(10, "Look-alikes: exact file, same DEX code, similar DEX code (TLSH)")
    st = fuzzy_hash.status()
    if st.status != "available":
        print("NOTE: py-tlsh isn't installed here, so the similar-code (TLSH) rows can't match.")
    limit = fuzzy_hash._tlsh_max_distance() * (1 - _threshold())
    print(f"A look-alike inherits a verdict when its DEX TLSH distance is <= {limit:.0f} "
          "(placeholder, calibrated on the test set).")

    def apk(dex, stored=False, extra=b""):
        return zip_of([("AndroidManifest.xml", MANIFEST), ("classes.dex", dex)], stored=stored, extra=extra)

    def row(svc, known, name, data):
        e, c, k = exact_hash.hash_bytes(data), content_hashes(data), content_hashes(known)
        dist = fuzzy_hash.tlsh_distance(k.dex_tlsh, c.dex_tlsh) if k.dex_tlsh and c.dex_tlsh else None
        res = svc.lookup(e, c)
        same_file = "=" if e.sha256 == exact_hash.hash_bytes(known).sha256 else "≠"
        same_dex = "=" if c.dex_sha256 == k.dex_sha256 else "≠"
        got = f"{res.verdict} via {res.matched_by}" if res.hit else "nothing -> full analysis"
        print(f"  {name:34s} file {same_file}  DEX {same_dex}  TLSH {'n/a' if dist is None else dist:>4}  -> {got}")

    bad_apk, good_apk = apk(BAD), apk(GOOD)
    svc = HashLookupService(store=VerdictStore(":memory:"))
    svc.record_verdict(exact_hash.hash_bytes(bad_apk).sha256, "malicious", content_hashes(bad_apk))
    print("Known MALICIOUS sample recorded (suspicious.dex). Its look-alikes:")
    row(svc, bad_apk, "the same file", bad_apk)
    row(svc, bad_apk, "re-zipped, re-signed, extra file", apk(BAD, stored=True, extra=b"re-signed"))
    row(svc, bad_apk, "repackaged: +200 bytes of code", apk(BAD + BAD[:200]))
    row(svc, bad_apk, "heavier repack: +400 bytes", apk(BAD + BAD[:400]))
    row(svc, bad_apk, "an unrelated app (benign.dex)", good_apk)

    svc = HashLookupService(store=VerdictStore(":memory:"))
    svc.record_verdict(exact_hash.hash_bytes(good_apk).sha256, "benign", content_hashes(good_apk))
    print("Known BENIGN sample recorded (benign.dex). Its look-alikes:")
    row(svc, good_apk, "the same file", good_apk)
    row(svc, good_apk, "near-copy: +200 bytes of code", apk(GOOD + GOOD[:200]))
    print("  -> 'benign' is never inherited by a look-alike: a repackaged bank app looks like the real one.")


def _threshold() -> float:
    from config import thresholds
    return float(thresholds()["verdict_inheritance_similarity"])


def _as_category(bundle, category):
    """The same analysis, re-run as if the app had declared `category`."""
    from dataclasses import replace

    from backend.static_analysis import api_usage
    obs = [replace(o, suspicious=api_usage._is_suspicious_for_category(o.category, category))
           for o in bundle.api_usage.observations]
    return replace(bundle, api_usage=replace(bundle.api_usage, observations=obs),
                   category=category, category_source="declared")


if __name__ == "__main__":
    main()
