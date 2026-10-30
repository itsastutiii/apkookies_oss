"""Code intelligence & evasion detection.

Responsibilities:
  * Extract the DEX string pool (feeds api_usage + ioc_extraction).
  * Detect obfuscation / packing (string encryption, reflection abuse,
    DexClassLoader dynamic loading, native stripping).
  * Call-graph / taint analysis (source -> sink) — heavy; delegated/stubbed.

Real logic: heuristic packer/obfuscation signals from string + entropy scans.
Bytecode cross-references (who calls what) live in dex_analysis.py; call-graph
taint analysis is not implemented.
"""
from __future__ import annotations

import logging
import math
import re
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from backend.common import apk_zip

logger = logging.getLogger(__name__)


class Obfuscation:
    STRING_ENCRYPTION = "string_encryption"
    REFLECTION = "reflection"
    DEX_CLASS_LOADER = "dex_class_loader"
    PACKER = "packer"
    NATIVE_STRIPPING = "native_stripping"


# --- Marker tables -----------------------------------------------------

_REFLECTION_MARKERS = (
    b"Ljava/lang/reflect/",
    b"Class.forName",
    b"getMethod",
    b"getDeclaredMethod",
    b"getDeclaredField",
    b"getConstructor",
    b"newInstance",
    b"invoke",
)
_DEX_LOADER_MARKERS = (b"DexClassLoader", b"PathClassLoader", b"InMemoryDexClassLoader")
_RUNTIME_MARKERS = (b"Runtime.exec", b"ProcessBuilder", b"su", b"chmod", b"busybox")
CRYPTO_MARKERS = (b"AES", b"RSA", b"DES", b"ECB", b"CBC", b"SecureRandom", b"MessageDigest", b"MD5", b"SHA1")
NETWORK_MARKERS = (b"OkHttp", b"Retrofit", b"Volley", b"HttpURLConnection", b"Socket", b"SSLContext", b"HostnameVerifier")
WEBVIEW_MARKERS = (b"setJavaScriptEnabled", b"addJavascriptInterface", b"setAllowFileAccess", b"setAllowUniversalAccessFromFileURLs")
ROOT_MARKERS = (b"/system/bin/su", b"/system/xbin/su", b"busybox", b"magisk", b"test-keys")
EMULATOR_MARKERS = (b"goldfish", b"ranchu", b"generic", b"Build.FINGERPRINT", b"Build.MODEL")
FRIDA_MARKERS = (b"frida", b"gum-js", b"xposed", b"substrate")
# Known packer artifact names (non-exhaustive). TODO: expand from research feeds.
_PACKER_SIGNS = (b"libjiagu", b"libDexHelper", b"libapp-super", b"libmobisec")

# --- Tunables ------------------------------------------------------------

_HIGH_ENTROPY_THRESHOLD = 7.2
_MIN_READABLE_STRINGS_FOR_UNPACKED = 20
_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{5,}")


@dataclass
class CodeIntelReport:
    # Obfuscation / Evasion
    obfuscation: list[str] = field(default_factory=list)

    # Behavior Categories
    reflection: list[str] = field(default_factory=list)
    dynamic_loading: list[str] = field(default_factory=list)
    runtime_execution: list[str] = field(default_factory=list)
    crypto_usage: list[str] = field(default_factory=list)
    networking: list[str] = field(default_factory=list)
    webview: list[str] = field(default_factory=list)
    root_detection: list[str] = field(default_factory=list)
    emulator_detection: list[str] = field(default_factory=list)
    anti_analysis: list[str] = field(default_factory=list)

    # DEX Information
    dex_strings: list[str] = field(default_factory=list)
    entropy_by_dex: dict[str, float] = field(default_factory=dict)

    taint_flows: list[str] = field(default_factory=list)  # TODO: real taint


# --- Public API ------------------------------------------------------------

def analyze(path: str | Path,
            dex_entries: list[tuple[str, bytes]] | None = None) -> CodeIntelReport:
    """Run lightweight heuristic code-intelligence analysis on an APK.

    `dex_entries` lets the caller pass DEX bytes it already read (one read per
    sample). Never raises on malformed input; a corrupt/unreadable APK simply
    yields a (mostly) empty report.
    """
    path = Path(path)
    report = CodeIntelReport()

    dex_pairs = dex_entries if dex_entries is not None else _read_dex_blobs_with_names(path)
    native_libs = _list_native_libs(path)

    strings: list[str] = []
    for name, blob in dex_pairs:
        report.entropy_by_dex[name] = _shannon_entropy(blob)
        strings.extend(_extract_strings(blob))
    report.dex_strings = _deduplicate(strings)

    # Marker scans run once over all DEX bytes (not once per DEX file).
    combined = b"".join(blob for _, blob in dex_pairs)
    report.reflection = _scan_reflection(combined)
    report.dynamic_loading = _scan_dynamic_loading(combined)
    report.runtime_execution = _scan_runtime(combined)
    report.crypto_usage = _scan_crypto(combined)
    report.networking = _scan_network(combined)
    report.webview = _scan_webview(combined)
    report.root_detection = _scan_root(combined)
    report.emulator_detection = _scan_emulator(combined)
    report.anti_analysis = _scan_frida(combined)
    report.obfuscation = _detect_obfuscation(
        combined=combined,
        entropy_by_dex=report.entropy_by_dex,
        dex_string_count=len(report.dex_strings),
        native_libs=native_libs,
    )
    # Call-graph / taint analysis is not implemented (taint_flows stays empty);
    # the shared bytecode analysis lives in dex_analysis.py.
    return report


# --- APK / DEX extraction helpers ------------------------------------------

def _read_dex_blobs_with_names(path: Path) -> list[tuple[str, bytes]]:
    """Return [(dex_name, bytes)] for every DEX (shared reader; see common/apk_zip)."""
    return apk_zip.read_dex_entries(path)


def _list_native_libs(path: Path) -> list[str]:
    """List native .so libraries bundled under lib/. Empty on failure."""
    try:
        with zipfile.ZipFile(path) as zf:
            return [
                n for n in zf.namelist()
                if n.startswith("lib/") and n.endswith(".so")
            ]
    except (zipfile.BadZipFile, OSError, FileNotFoundError):
        return []


def _extract_strings(blob: bytes) -> list[str]:
    """Extract printable ASCII strings (len >= 5) from a DEX blob."""
    return [
        s.decode("latin-1", errors="ignore")
        for s in _PRINTABLE_RE.findall(blob)
        if _is_useful_string(s)
    ]


def _is_useful_string(raw: bytes) -> bool:
    """Filter out low-signal strings (e.g. pure whitespace/padding runs)."""
    return len(raw.strip()) >= 5


# --- Marker scanning helpers -------------------------------------------

def _find_markers(data: bytes, markers: tuple[bytes, ...]) -> list[str]:
    """Return the decoded marker names present in `data`, deduplicated."""
    found = [m.decode("ascii", errors="ignore") for m in markers if m in data]
    return _deduplicate(found)


def _scan_reflection(data: bytes) -> list[str]:
    return _find_markers(data, _REFLECTION_MARKERS)


def _scan_dynamic_loading(data: bytes) -> list[str]:
    return _find_markers(data, _DEX_LOADER_MARKERS)


def _scan_runtime(data: bytes) -> list[str]:
    return _find_markers(data, _RUNTIME_MARKERS)


def _scan_crypto(data: bytes) -> list[str]:
    return _find_markers(data, CRYPTO_MARKERS)


def _scan_network(data: bytes) -> list[str]:
    return _find_markers(data, NETWORK_MARKERS)


def _scan_webview(data: bytes) -> list[str]:
    return _find_markers(data, WEBVIEW_MARKERS)


def _scan_root(data: bytes) -> list[str]:
    return _find_markers(data, ROOT_MARKERS)


def _scan_emulator(data: bytes) -> list[str]:
    return _find_markers(data, EMULATOR_MARKERS)


def _scan_frida(data: bytes) -> list[str]:
    return _find_markers(data, FRIDA_MARKERS)


def _scan_packer(data: bytes) -> list[str]:
    return _find_markers(data, _PACKER_SIGNS)


# --- Obfuscation heuristics -------------------------------------------

def _detect_obfuscation(
    *,
    combined: bytes,
    entropy_by_dex: dict[str, float],
    dex_string_count: int,
    native_libs: list[str],
) -> list[str]:
    """Aggregate obfuscation/packing signals into a deduplicated list."""
    signals: list[str] = []

    if _scan_packer(combined):
        signals.append(Obfuscation.PACKER)

    if _scan_reflection(combined):
        signals.append(Obfuscation.REFLECTION)

    if _scan_dynamic_loading(combined):
        signals.append(Obfuscation.DEX_CLASS_LOADER)

    max_entropy = max(entropy_by_dex.values(), default=0.0)

    # High-entropy DEX with few readable strings -> likely encrypted/packed.
    if (
        max_entropy > _HIGH_ENTROPY_THRESHOLD
        and dex_string_count < 100
    ):
        signals.append(Obfuscation.STRING_ENCRYPTION)

    # Native libs present alongside a sparse, high-entropy DEX suggests the
    # real logic was moved/stripped into native code.
    if (
        native_libs
        and dex_string_count < _MIN_READABLE_STRINGS_FOR_UNPACKED
        and max_entropy > _HIGH_ENTROPY_THRESHOLD
    ):
        signals.append(Obfuscation.NATIVE_STRIPPING)

    return _deduplicate(signals)


# --- Generic utilities ---------------------------------------------------

def _deduplicate(items: list[str]) -> list[str]:
    """Deduplicate while keeping a stable, sorted order."""
    return sorted(set(items))


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())