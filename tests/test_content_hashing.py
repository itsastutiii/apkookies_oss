"""Content hashing + verdict-inheritance safety rules.

Fixtures are small zip archives built in memory with fake DEX/manifest bytes,
not real or installable APKs.
"""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from backend.hashing import clustering, exact_hash, fuzzy_hash
from backend.hashing.clustering import VariantClusterStore
from backend.hashing.content_hash import ContentHashes, content_hashes
from backend.hashing.lookup import HashLookupService

DEX1 = b"dex\n035\x00" + b"\x11" * 300
DEX2 = b"dex\n035\x00" + b"\x22" * 300
MANIFEST = b"\x03\x00\x08\x00" + b"\x7f" * 120


def make_zip(entries: list[tuple[str, bytes]], *, compression=zipfile.ZIP_DEFLATED,
             extra: bytes = b"") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compression) as zf:
        for name, data in entries:
            zf.writestr(name, data)
        if extra:
            zf.writestr("META-INF/CERT.RSA", extra)  # stands in for a different signature
    return buf.getvalue()


ORIGINAL = make_zip([("AndroidManifest.xml", MANIFEST), ("classes.dex", DEX1),
                     ("classes2.dex", DEX2)])
# Same code, different container: re-ordered, stored instead of deflated, "re-signed".
REZIPPED = make_zip([("classes2.dex", DEX2), ("classes.dex", DEX1),
                     ("AndroidManifest.xml", MANIFEST)],
                    compression=zipfile.ZIP_STORED, extra=b"other signer")


def test_content_hash_survives_rezip_and_resign():
    a, b = content_hashes(ORIGINAL), content_hashes(REZIPPED)
    assert exact_hash.hash_bytes(ORIGINAL).sha256 != exact_hash.hash_bytes(REZIPPED).sha256
    assert a.dex_count == 2
    assert a.dex_sha256 == b.dex_sha256 is not None
    assert a.manifest_sha256 == b.manifest_sha256 is not None


def test_dex_order_is_load_order_not_zip_order():
    many = [(f"classes{i}.dex", bytes([i]) * 64) for i in (10, 2, 3)] + [("classes.dex", b"x" * 64)]
    shuffled = list(reversed(many))
    assert content_hashes(make_zip(many)).dex_sha256 == content_hashes(make_zip(shuffled)).dex_sha256


def test_non_zip_yields_empty_content_hashes():
    c = content_hashes(b"not a zip at all")
    assert c.dex_count == 0 and c.dex_sha256 is None and c.manifest_sha256 is None


def _service() -> HashLookupService:
    return HashLookupService(clusters=VariantClusterStore(similarity_threshold=0.90))


def test_rezipped_variant_inherits_malicious():
    svc = _service()
    svc.record_verdict(exact_hash.hash_bytes(ORIGINAL).sha256, "malicious",
                       content_hashes(ORIGINAL))
    res = svc.lookup(exact_hash.hash_bytes(REZIPPED), content_hashes(REZIPPED))
    assert res.hit and res.verdict == "malicious" and res.matched_by == "dex_exact"


def test_benign_is_never_inherited_by_content_match():
    """A repackaged bank app has the genuine app's code: it must NOT come back benign."""
    svc = _service()
    genuine_sha = exact_hash.hash_bytes(ORIGINAL).sha256
    svc.record_verdict(genuine_sha, "benign", content_hashes(ORIGINAL))

    repackaged = svc.lookup(exact_hash.hash_bytes(REZIPPED), content_hashes(REZIPPED))
    assert not repackaged.hit and repackaged.verdict is None

    # The exact same file still gets its benign verdict back.
    same = svc.lookup(exact_hash.hash_bytes(ORIGINAL), content_hashes(ORIGINAL))
    assert same.hit and same.verdict == "benign" and same.matched_by == "exact"


def _fake_fuzzy(monkeypatch, similarity: float):
    monkeypatch.setattr(clustering, "normalized_similarity", lambda a, b: similarity)


def _with_fuzzy(dex_sha: str) -> ContentHashes:
    return ContentHashes(dex_count=1, dex_sha256=dex_sha, dex_ssdeep="3:abc:def")


def test_fuzzy_match_inherits_only_malicious(monkeypatch):
    _fake_fuzzy(monkeypatch, 0.95)
    svc = _service()
    svc.record_verdict("a" * 64, "benign", _with_fuzzy("1" * 64))
    assert not svc.lookup(exact_hash.ExactHashes("", "b" * 64, 0), _with_fuzzy("2" * 64)).hit

    svc.record_verdict("c" * 64, "malicious", _with_fuzzy("3" * 64))
    res = svc.lookup(exact_hash.ExactHashes("", "d" * 64, 0), _with_fuzzy("4" * 64))
    assert res.hit and res.verdict == "malicious" and res.matched_by == "fuzzy"


def test_fuzzy_below_threshold_is_a_miss(monkeypatch):
    _fake_fuzzy(monkeypatch, 0.5)
    svc = _service()
    svc.record_verdict("a" * 64, "malicious", _with_fuzzy("1" * 64))
    assert not svc.lookup(exact_hash.ExactHashes("", "b" * 64, 0), _with_fuzzy("2" * 64)).hit


def test_lookup_is_read_only(monkeypatch):
    _fake_fuzzy(monkeypatch, 0.0)
    svc = _service()
    for i in range(5):
        svc.lookup(exact_hash.ExactHashes("", f"{i}" * 64, 0), _with_fuzzy(f"{i}" * 64))
    assert len(svc.clusters) == 0


@pytest.mark.parametrize("ssdeep_mod,tlsh_mod,expected", [
    (None, None, "unavailable"),
    (object(), None, "partial"),      # TLSH (primary) missing
    (None, object(), "available"),    # ssdeep is optional
    (object(), object(), "available"),
])
def test_fuzzy_status_is_reported(monkeypatch, ssdeep_mod, tlsh_mod, expected):
    monkeypatch.setattr(fuzzy_hash, "_ssdeep", ssdeep_mod)
    monkeypatch.setattr(fuzzy_hash, "_tlsh", tlsh_mod)
    st = fuzzy_hash.status()
    assert st.status == expected
    assert (st.note is None) == (expected == "available")
    if expected == "unavailable":
        assert "not installed" in st.note


def test_lookup_carries_fuzzy_status(monkeypatch):
    monkeypatch.setattr(fuzzy_hash, "_ssdeep", None)
    monkeypatch.setattr(fuzzy_hash, "_tlsh", None)
    res = _service().lookup(exact_hash.hash_bytes(ORIGINAL), content_hashes(ORIGINAL))
    assert res.fuzzy_status == "unavailable" and "not installed" in res.fuzzy_note


def test_inheritance_threshold_comes_from_config():
    from config import thresholds

    assert VariantClusterStore().threshold == thresholds()["verdict_inheritance_similarity"]


def test_unparseable_manifest_is_never_benign():
    """A zip that only *looks* like an APK must not get a benign verdict."""
    import tempfile
    from pathlib import Path

    from backend.scoring.risk_score import score_static
    from backend.static_analysis import run as run_static

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "fake.zip"
        p.write_bytes(ORIGINAL)
        bundle = run_static(p)
    assert bundle.analysis_status["manifest"]["status"] == "failed"
    risk = score_static(bundle)
    assert risk.verdict_label != "benign"
    assert any("manifest could not be parsed" in f for f in risk.contributing_factors)


try:
    import tlsh
except ImportError:  # pragma: no cover - CI and the pinned env have py-tlsh
    tlsh = None
needs_tlsh = pytest.mark.skipif(tlsh is None, reason="py-tlsh not installed")
FIXTURE_DEX = Path(__file__).parent / "fixtures" / "dex"


@needs_tlsh
def test_tlsh_is_primary_and_runs_on_real_dex():
    assert fuzzy_hash.status().status == "available"
    bad = (FIXTURE_DEX / "suspicious.dex").read_bytes()
    good = (FIXTURE_DEX / "benign.dex").read_bytes()
    a = content_hashes(make_zip([("AndroidManifest.xml", MANIFEST), ("classes.dex", bad)]))
    b = content_hashes(make_zip([("classes.dex", bad), ("AndroidManifest.xml", MANIFEST)],
                                compression=zipfile.ZIP_STORED))
    c = content_hashes(make_zip([("AndroidManifest.xml", MANIFEST), ("classes.dex", good)]))
    assert a.dex_tlsh and a.dex_tlsh == b.dex_tlsh
    assert fuzzy_hash.normalized_similarity(a.dex_fuzzy, b.dex_fuzzy) == 1.0
    variant = content_hashes(make_zip([("classes.dex", bad + bad[:400])])).dex_fuzzy
    unrelated = fuzzy_hash.normalized_similarity(a.dex_fuzzy, c.dex_fuzzy)
    assert unrelated < 0.5
    assert fuzzy_hash.normalized_similarity(a.dex_fuzzy, variant) > unrelated


@needs_tlsh
def test_tlsh_used_before_ssdeep(monkeypatch):
    class FakeSsdeep:
        @staticmethod
        def compare(x, y):
            raise AssertionError("ssdeep must not be used when TLSH can compare")
    monkeypatch.setattr(fuzzy_hash, "_ssdeep", FakeSsdeep)
    h = tlsh.hash((FIXTURE_DEX / "suspicious.dex").read_bytes())
    same = fuzzy_hash.FuzzyHashes(ssdeep="3:a:b", tlsh=h)
    assert fuzzy_hash.normalized_similarity(same, same) == 1.0


@needs_tlsh
def test_real_fuzzy_inheritance_end_to_end():
    """With real TLSH: a malicious DEX's near-copy inherits malicious; never benign."""
    bad = (FIXTURE_DEX / "suspicious.dex").read_bytes()
    original = make_zip([("AndroidManifest.xml", MANIFEST), ("classes.dex", bad)])
    near_copy = make_zip([("AndroidManifest.xml", MANIFEST), ("classes.dex", bad + b"\x00" * 8)])
    svc = HashLookupService(clusters=VariantClusterStore(similarity_threshold=0.90))
    svc.record_verdict(exact_hash.hash_bytes(original).sha256, "malicious", content_hashes(original))
    res = svc.lookup(exact_hash.hash_bytes(near_copy), content_hashes(near_copy))
    assert res.hit and res.verdict == "malicious" and res.matched_by == "fuzzy"

    svc2 = HashLookupService(clusters=VariantClusterStore(similarity_threshold=0.90))
    svc2.record_verdict(exact_hash.hash_bytes(original).sha256, "benign", content_hashes(original))
    assert not svc2.lookup(exact_hash.hash_bytes(near_copy), content_hashes(near_copy)).hit
