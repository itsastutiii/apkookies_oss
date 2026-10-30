"""Content hashes: hashes of what's INSIDE the APK, not of the zip container.

Whole-APK hashes change whenever an APK is re-zipped (different compression,
entry order, timestamps) or re-signed (META-INF), even if not one byte of code
changed. Hashing the uncompressed DEX bytecode and the binary manifest gives an
identity that survives both, so a known-malicious payload is still recognised
after repackaging.

- dex_*: all classes*.dex concatenated in load order (classes.dex, classes2.dex, ...).
- manifest_*: the binary AndroidManifest.xml (reported for analysts and later
  calibration; NOT used for verdict inheritance, since manifests are short and
  many apps share near-identical ones).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from backend.common import apk_zip
from backend.hashing.fuzzy_hash import FuzzyHashes, fuzzy_hash_bytes


@dataclass(frozen=True)
class ContentHashes:
    dex_count: int = 0
    dex_sha256: Optional[str] = None
    dex_ssdeep: Optional[str] = None
    dex_tlsh: Optional[str] = None
    manifest_sha256: Optional[str] = None
    manifest_ssdeep: Optional[str] = None
    manifest_tlsh: Optional[str] = None

    @property
    def dex_fuzzy(self) -> FuzzyHashes:
        return FuzzyHashes(ssdeep=self.dex_ssdeep, tlsh=self.dex_tlsh)


def content_hashes(source: str | Path | bytes) -> ContentHashes:
    """Hash the uncompressed DEX contents and binary manifest of an APK."""
    dex = apk_zip.read_dex_entries(source)
    manifest = apk_zip.read_entry(source, apk_zip.MANIFEST)

    dex_sha = dex_fuzzy = None
    if dex:
        sha = hashlib.sha256()
        for _, blob in dex:
            sha.update(blob)
        dex_sha = sha.hexdigest()
        dex_fuzzy = fuzzy_hash_bytes(b"".join(blob for _, blob in dex))

    man_fuzzy = fuzzy_hash_bytes(manifest) if manifest else None
    return ContentHashes(
        dex_count=len(dex),
        dex_sha256=dex_sha,
        dex_ssdeep=dex_fuzzy.ssdeep if dex_fuzzy else None,
        dex_tlsh=dex_fuzzy.tlsh if dex_fuzzy else None,
        manifest_sha256=hashlib.sha256(manifest).hexdigest() if manifest else None,
        manifest_ssdeep=man_fuzzy.ssdeep if man_fuzzy else None,
        manifest_tlsh=man_fuzzy.tlsh if man_fuzzy else None,
    )
