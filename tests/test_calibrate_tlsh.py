"""TLSH threshold calibration on a tiny synthetic "test set" built from the DEX fixtures."""
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from backend.hashing import fuzzy_hash
from ml.eval import calibrate_tlsh as cal

FIX = Path(__file__).parent / "fixtures" / "dex"
pytestmark = pytest.mark.skipif(fuzzy_hash.status().status != "available", reason="needs py-tlsh")


def _apk(path: Path, dex: bytes) -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("classes.dex", dex)
    path.write_bytes(buf.getvalue())
    return path.name


def test_calibration_keeps_benign_out_and_reports_recall(tmp_path):
    bad, good = (FIX / "suspicious.dex").read_bytes(), (FIX / "benign.dex").read_bytes()
    rows = [
        (_apk(tmp_path / "t1.apk", bad), "malicious", "banking_trojan", "famA"),
        (_apk(tmp_path / "t2.apk", bad + bad[:200]), "malicious", "banking_trojan", "famA"),
        (_apk(tmp_path / "t3.apk", bad + bad[:400]), "malicious", "banking_trojan", "famA"),
        (_apk(tmp_path / "t4.apk", bad), "malicious", "banking_trojan", "famA"),      # identical DEX
        (_apk(tmp_path / "b1.apk", good), "benign", "other_benign", ""),
        (_apk(tmp_path / "b2.apk", good + good[:200]), "benign", "other_benign", ""),
    ]
    labels = tmp_path / "labels.csv"
    labels.write_text("path,label,group,family\n" + "".join(f"{p},{l},{g},{f}\n" for p, l, g, f in rows))
    assert cal.main([str(labels), "--out", str(tmp_path / "out")]) == 0
    r = json.loads((tmp_path / "out" / "tlsh_calibration.json").read_text())
    assert r["samples"]["malicious"] == 4 and r["samples"]["families"] == 1
    assert r["pairs_with_identical_dex"] == 1
    assert r["at_current"]["malicious_benign_matches"] == 0
    # The closest malicious<->benign pair sets the ceiling; nothing benign falls under it.
    assert r["at_suggested"]["malicious_benign_matches"] == 0
    assert r["suggested_max_distance"] == r["distances"]["malicious_benign"]["min"] - cal.SAFETY_MARGIN
    assert 0 < r["at_current"]["same_family_recall"] <= 1
    assert r["suggested_config"]["tlsh_max_distance"] == 300
    out = (tmp_path / "out" / "tlsh_calibration.json").read_text()
    assert str(tmp_path) not in out and ".apk" not in out          # no paths in committed output
