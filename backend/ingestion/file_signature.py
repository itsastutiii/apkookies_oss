"""Content-type detection by file signature (magic bytes) — never trust headers.

A phishing host commonly serves an APK with `Content-Type: text/html`, or an
HTML lure with a `.apk` link. The pipeline branches on ACTUAL bytes, not the
server's claim or the URL extension.

Real logic here (zip/APK detection works with stdlib); libmagic is used when
available for broader coverage.
"""
from __future__ import annotations

import zipfile
from enum import Enum
from io import BytesIO
from pathlib import Path

try:  # optional, broader coverage
    import magic as _libmagic
except ImportError:  # pragma: no cover
    _libmagic = None


class ContentKind(str, Enum):
    apk = "apk"
    zip = "zip"
    html = "html"
    dex = "dex"
    elf = "elf"
    pdf = "pdf"
    unknown = "unknown"


# Leading-byte signatures (order matters; check most specific first).
_SIGNATURES: list[tuple[bytes, ContentKind]] = [
    (b"dex\n", ContentKind.dex),        # 64 65 78 0A -> classes.dex
    (b"\x7fELF", ContentKind.elf),       # native .so
    (b"%PDF-", ContentKind.pdf),
]


def _looks_like_html(head: bytes) -> bool:
    sniff = head[:512].lstrip().lower()
    return sniff.startswith(b"<!doctype html") or sniff.startswith(b"<html") or b"<head" in sniff


def _zip_is_apk(data: bytes) -> bool:
    """A ZIP is an APK if it contains AndroidManifest.xml + classes*.dex."""
    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            names = set(zf.namelist())
            has_manifest = "AndroidManifest.xml" in names
            has_dex = any(n == "classes.dex" or (n.startswith("classes") and n.endswith(".dex"))
                          for n in names)
            return has_manifest and has_dex
    except zipfile.BadZipFile:
        return False


def detect_bytes(data: bytes) -> ContentKind:
    head = data[:16]
    for sig, kind in _SIGNATURES:
        if head.startswith(sig):
            return kind

    # ZIP local-file-header -> could be APK or plain zip.
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return ContentKind.apk if _zip_is_apk(data) else ContentKind.zip

    if _looks_like_html(data):
        return ContentKind.html

    # Fallback: libmagic if present.
    if _libmagic:
        mime = _libmagic.from_buffer(data, mime=True)
        if mime == "text/html":
            return ContentKind.html
        if mime in ("application/vnd.android.package-archive", "application/zip"):
            return ContentKind.apk if _zip_is_apk(data) else ContentKind.zip

    return ContentKind.unknown


def detect_file(path: str | Path) -> ContentKind:
    data = Path(path).read_bytes()
    return detect_bytes(data)
