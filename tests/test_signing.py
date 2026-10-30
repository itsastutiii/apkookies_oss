"""Signing-certificate analysis and the bank allowlist (certificates generated in-test)."""
from __future__ import annotations

import datetime as dt

import pytest
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from backend.scoring.rules_engine import RuleContext, _bank_impersonation
from backend.static_analysis import signing


def make_cert(common_name: str, org: str = "Example") -> asn1_x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                      x509.NameAttribute(NameOID.COUNTRY_NAME, "US")])
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    return asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))


def test_summarize_fingerprints_and_debug():
    debug = make_cert("Android Debug", "Android")
    release = make_cert("Some Bank Ltd")
    infos = signing.summarize([debug, release, release])
    assert len(infos) == 2  # deduplicated
    by_cn = {("Android Debug" in i.subject): i for i in infos}
    assert by_cn[True].debug and not by_cn[False].debug
    assert by_cn[False].sha256 == release.sha256.hex() and len(by_cn[False].sha256) == 64
    assert by_cn[False].not_before.startswith("2026-01-01")


ENTRIES = ({"bank": "Test Bank", "packages": {"com.testbank.app"},
            "app_names": {"testbank mobile"}, "certs": {"aa" * 32}},)


@pytest.mark.parametrize("package,name,fps,status,matched_by", [
    ("com.testbank.app", None, ["aa" * 32], "genuine", "package"),
    ("com.testbank.app", None, ["bb" * 32], "impersonation", "package"),
    ("com.other.app", "TestBank Mobile", ["bb" * 32], "impersonation", "app_name"),  # copied label
    ("com.other.app", "Other", ["bb" * 32], "not_listed", None),
    ("com.testbank.app", None, [], "unavailable", "package"),
])
def test_allowlist(package, name, fps, status, matched_by):
    res = signing.check_allowlist(package, name, fps, entries=ENTRIES)
    assert res.status == status and res.matched_by == matched_by
    if status != "not_listed":
        assert res.bank == "Test Bank"


def test_package_match_takes_precedence_over_name_match():
    entries = ENTRIES + ({"bank": "Other Bank", "packages": {"com.otherbank"},
                          "app_names": {"testbank mobile"}, "certs": {"cc" * 32}},)
    # Genuine Test Bank package + cert, even though its label matches Other Bank's list.
    res = signing.check_allowlist("com.testbank.app", "TestBank Mobile", ["aa" * 32], entries=entries)
    assert res.status == "genuine" and res.bank == "Test Bank"


def test_allowlist_fingerprint_format_is_normalized(tmp_path):
    p = tmp_path / "allow.yaml"
    colon = ":".join(["AA"] * 32)
    p.write_text("banks:\n  - bank: B\n    packages: [com.b]\n    cert_sha256: ['%s']\n"
                 "  - bank: NoCert\n    packages: [com.c]\n" % colon, encoding="utf-8")
    signing.load_allowlist.cache_clear()
    entries = signing.load_allowlist(str(p))
    signing.load_allowlist.cache_clear()
    assert [e["bank"] for e in entries] == ["B"]  # entry without a certificate is ignored
    assert signing.check_allowlist("com.b", None, ["aa" * 32], entries=entries).status == "genuine"


def test_shipped_allowlist_is_an_empty_template():
    assert signing.load_allowlist() == ()


BASE = dict(permissions=set(), app_category=None, suspicious_api_categories=set(), api_categories=set(),
            anti_analysis_techniques=set(), has_telegram_token=False)


def test_package_impersonation_is_a_hard_block_floor():
    assert _bank_impersonation(RuleContext(**BASE)) is None
    hit = _bank_impersonation(RuleContext(**BASE, bank_impersonation="fake",
                                          bank_impersonation_by="package"))
    assert hit.rule_id == "R004_BANK_IMPERSONATION" and hit.hard_override and hit.min_score == 0.90


def test_name_only_lookalike_is_warning_level():
    from config import thresholds

    hit = _bank_impersonation(RuleContext(**BASE, bank_impersonation="look-alike",
                                          bank_impersonation_by="app_name"))
    assert hit.rule_id == "R004B_BANK_NAME_LOOKALIKE"
    assert not hit.hard_override and hit.min_score == 0.40
    # 0.40 must be "warn" (not allow, not block) on every touchpoint policy.
    for name, band in thresholds()["response_policy"].items():
        assert band["allow_below"] <= hit.min_score < band["block_at_or_above"], name


def test_cert_reuse_store():
    from backend.threat_intel.cert_reuse import CertReuseStore

    store = CertReuseStore()
    store.record(["k1"], "s1", "malicious")
    store.record(["k1"], "s2", "benign")
    assert store.lookup(["k1"], exclude_sha256="s3") == (2, 1)
    assert store.lookup(["k1"], exclude_sha256="s1") == (1, 0)
    assert store.lookup(["k2"]) == (0, 0)


@pytest.mark.parametrize("matched_by,low,high,escalates", [
    ("app_name", 0.40, 0.55, True),    # warn band; sandbox escalation still possible
    ("package", 0.90, 1.01, False),    # block; hard override
])
def test_r004_floors_applied_in_scoring(tmp_path, matched_by, low, high, escalates):
    import io
    import zipfile
    from pathlib import Path

    from backend.scoring.risk_score import score_static
    from backend.static_analysis import run as run_static

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 64)
        zf.writestr("classes.dex", (Path(__file__).parent / "fixtures/dex/benign.dex").read_bytes())
    p = tmp_path / "s.zip"
    p.write_bytes(buf.getvalue())
    bundle = run_static(p)
    bundle.structural.signing.allowlist = signing.AllowlistResult(
        "impersonation", "Test Bank", "claims Test Bank", matched_by)
    risk = score_static(bundle)
    assert low <= risk.score < high
    assert risk.needs_dynamic_analysis is escalates


def test_allowlist_checker(tmp_path):
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "check_bank_allowlist", Path(__file__).resolve().parents[1] / "scripts/check_bank_allowlist.py")
    chk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(chk)
    assert chk.check(chk.DEFAULT) == []  # the shipped empty template is valid
    bad = tmp_path / "b.yaml"
    bad.write_text("banks:\n  - bank: A\n    packages: [com.x]\n    cert_sha256: ['abc']\n"
                   "  - bank: B\n    packages: [com.x]\n    cert_sha256: ['" + "aa" * 32 + "']\n"
                   "    source: s\n    collected_by: c\n", encoding="utf-8")
    problems = chk.check(bad)
    assert any("not 64 hex" in p for p in problems)
    assert any("missing 'source'" in p for p in problems)
    assert any("also listed under A" in p for p in problems)
