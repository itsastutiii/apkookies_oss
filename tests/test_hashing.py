"""Hashing layer tests (exact hashing has no optional deps -> always runs)."""
from __future__ import annotations

import hashlib

from backend.hashing import exact_hash


def test_exact_hash_bytes_matches_hashlib():
    data = b"hello apkookies"
    result = exact_hash.hash_bytes(data)
    assert result.sha256 == hashlib.sha256(data).hexdigest()
    assert result.md5 == hashlib.md5(data).hexdigest()
    assert result.size_bytes == len(data)


def test_hash_stream_equals_hash_bytes(tmp_path):
    data = b"a" * (2 * (1 << 20) + 7)  # spans multiple chunks
    p = tmp_path / "blob.bin"
    p.write_bytes(data)
    assert exact_hash.hash_file(p).sha256 == exact_hash.hash_bytes(data).sha256
