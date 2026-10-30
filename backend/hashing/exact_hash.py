"""Exact hashing: tier-1 fast path.

MD5 + SHA-256 are computed in a single streaming pass so large APKs never fully
load into memory. SHA-256 is the canonical identity; MD5 kept for interop with
legacy feeds (e.g. some ThreatFox / VT records).

This module has NO heavy dependencies and is the first thing every entry point
(browser extension endpoint, sandbox gate, dedup) calls.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

_CHUNK = 1 << 20  # 1 MiB


@dataclass(frozen=True)
class ExactHashes:
    md5: str
    sha256: str
    size_bytes: int


def hash_stream(fh: BinaryIO) -> ExactHashes:
    """Compute MD5 + SHA-256 in a single streaming pass over an open binary file."""
    md5 = hashlib.md5()  # noqa: S324 - not used for security, interop only
    sha256 = hashlib.sha256()
    size = 0
    while chunk := fh.read(_CHUNK):
        md5.update(chunk)
        sha256.update(chunk)
        size += len(chunk)
    return ExactHashes(md5=md5.hexdigest(), sha256=sha256.hexdigest(), size_bytes=size)


def hash_file(path: str | Path) -> ExactHashes:
    with open(path, "rb") as fh:
        return hash_stream(fh)


def hash_bytes(data: bytes) -> ExactHashes:
    return ExactHashes(
        md5=hashlib.md5(data).hexdigest(),  # noqa: S324
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )
