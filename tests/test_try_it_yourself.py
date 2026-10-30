"""The review docs' 5-minute demo must keep working."""
import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "try_it_yourself.py"


def test_tour_runs(capsys):
    spec = importlib.util.spec_from_file_location("try_it_yourself", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.main()
    out = capsys.readouterr().out
    assert "DEX-content SHA-256 equal?  True" in out
    assert "original stored as benign    -> re-zipped copy gets: nothing" in out
    assert "benign.dex (has decoy text): http_client" in out
    assert "no category): R002_A11Y_OVERLAY(stage 3) -> score 0.44, warn, sandbox" in out
    assert "data-flow behaviour (Quark): R002_A11Y_OVERLAY(stage 3), R005_BEHAVIOUR(stage 5) -> score 0.90, block" in out
    assert "(password-manager-like): rules = ['R002B_A11Y_OVERLAY_ALONE'] score 0.44 -> ['warn']" in out
    assert "= sum of the deltas" in out and "rule:R003_TELEGRAM_C2" in out
    assert "-> 0.400  R003_TELEGRAM_C2 sets a minimum of 0.40 (warn-level)." in out
    assert "re-zipped copy -> nothing (benign never spreads)" in out
    # Section 10: look-alikes, tier by tier (the TLSH tier needs py-tlsh).
    from backend.hashing import fuzzy_hash
    assert "re-zipped, re-signed, extra file   file ≠  DEX =" in out and "malicious via dex_exact" in out
    if fuzzy_hash.status().status == "available":
        assert "repackaged: +200 bytes of code     file ≠  DEX ≠  TLSH   15  -> malicious via fuzzy" in out
        assert "near-copy: +200 bytes of code      file ≠  DEX ≠  TLSH   19  -> nothing -> full analysis" in out
    else:
        assert "py-tlsh isn't installed" in out
    assert "after retraining: known? False | stale verdict: malicious" in out
