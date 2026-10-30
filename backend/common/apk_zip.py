"""Read raw entries (DEX files, binary manifest) out of an APK.

Shared by hashing (content hashes) and static analysis (code_intel), so both
see exactly the same bytes. Works on a path or on in-memory bytes.

Some samples set the zip "encrypted" general-purpose bit without any real
encryption, a cheap anti-tooling trick: Python's zipfile refuses to read such
entries (RuntimeError). We fall back to androguard's own zip handling, which
ignores that flag, before giving up.
"""
from __future__ import annotations

import io
import logging
import re
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)

MANIFEST = "AndroidManifest.xml"
_DEX_NAME_RE = re.compile(r"^classes(\d*)\.dex$")


def _dex_order(name: str) -> tuple[int, str]:
    """classes.dex, classes2.dex, ..., classes10.dex, then any other .dex by name."""
    m = _DEX_NAME_RE.match(name)
    if m:
        return (int(m.group(1) or 1), name)
    return (10**6, name)


def _open(source: str | Path | bytes) -> zipfile.ZipFile:
    if isinstance(source, (bytes, bytearray)):
        return zipfile.ZipFile(io.BytesIO(source))
    return zipfile.ZipFile(source)


def _androguard_apk(source: str | Path | bytes):
    from androguard.core.apk import APK  # type: ignore

    if isinstance(source, (bytes, bytearray)):
        return APK(bytes(source), raw=True)
    return APK(str(source))


def read_dex_entries(source: str | Path | bytes) -> list[tuple[str, bytes]]:
    """Return [(dex_name, uncompressed bytes)] in DEX load order. Empty on failure."""
    try:
        with _open(source) as zf:
            names = sorted((n for n in zf.namelist() if n.endswith(".dex")), key=_dex_order)
            return [(n, zf.read(n)) for n in names]
    except RuntimeError:
        pass  # bogus "encrypted" flag -> androguard below
    except Exception as e:
        logger.warning("Could not read DEX entries: %r", e)
        return []
    try:
        apk = _androguard_apk(source)
        return [
            (f"classes{'' if i == 0 else i + 1}.dex", blob)
            for i, blob in enumerate(apk.get_all_dex())
        ]
    except Exception as e:
        logger.warning("Could not read DEX entries: %r", e)
        return []


def read_entry(source: str | Path | bytes, name: str) -> bytes | None:
    """Return one entry's uncompressed bytes, or None if absent/unreadable."""
    try:
        with _open(source) as zf:
            return zf.read(name)
    except KeyError:
        return None
    except RuntimeError:
        pass  # bogus "encrypted" flag -> androguard below
    except Exception as e:
        logger.warning("Could not read %s: %r", name, e)
        return None
    try:
        return _androguard_apk(source).get_file(name) or None
    except Exception as e:
        logger.warning("Could not read %s: %r", name, e)
        return None


def list_entries(source: str | Path | bytes) -> list[str]:
    """Return entry names, or [] if the archive can't be opened."""
    try:
        with _open(source) as zf:
            return zf.namelist()
    except Exception:
        return []
