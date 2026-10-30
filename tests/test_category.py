"""One category method for static analysis, scoring and training ."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

from backend.scoring import rules_engine
from backend.scoring.category import infer_category as scoring_infer
from backend.static_analysis import run as run_static
from backend.static_analysis.category import resolve_category

FIX = Path(__file__).parent / "fixtures" / "dex"


def _apk(tmp_path, dex: str) -> Path:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", b"garbage")   # unreadable: no declared category
        z.writestr("classes.dex", (FIX / f"{dex}.dex").read_bytes())
    p = tmp_path / f"{dex}.zip"
    p.write_bytes(buf.getvalue())
    return p


def test_resolution_order():
    assert resolve_category("Game", "com.example.bank", []) == ("Game", "declared")
    assert resolve_category(None, "com.example.bank", []) == ("Banking", "inferred")
    assert resolve_category(None, "com.example.x", ["nothing here"]) == (None, "none")


def test_sms_strings_do_not_make_an_app_communication():
    # The SMS-stealer fixture loads "content://sms/inbox"; that must not exempt it.
    assert resolve_category(None, None, ["content://sms/inbox"]) == (None, "none")


def test_static_analysis_uses_the_resolved_category_for_api_suspicion(tmp_path, monkeypatch):
    from backend.static_analysis import category as category_mod

    monkeypatch.setattr(category_mod, "resolve_category",
                        lambda declared, pkg, strings: ("Banking", "inferred"))
    bundle = run_static(_apk(tmp_path, "suspicious"))
    assert (bundle.category, bundle.category_source) == ("Banking", "inferred")
    suspicious = {o.category.value for o in bundle.api_usage.observations if o.suspicious}
    # Only categories with a sourced ANOMALOUS_FOR edge for Banking (accessibility);
    # SMS is normal for bank apps (OTP auto-read, UPI device binding).
    assert suspicious == {"accessibility"}
    assert bundle.analysis_status["category"]["status"] == "heuristic"
    # Scoring and the rules read the same value, so R002 now fires on real bytecode.
    assert scoring_infer(bundle) == "Banking"
    assert "R002_A11Y_OVERLAY" in {h.rule_id for h in rules_engine.evaluate(bundle)}


def test_no_category_is_reported_as_unavailable(tmp_path):
    bundle = run_static(_apk(tmp_path, "benign"))
    assert bundle.category is None and bundle.category_source == "none"
    assert bundle.analysis_status["category"]["status"] == "unavailable"
