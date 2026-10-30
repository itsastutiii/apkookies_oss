"""Signing-certificate analysis: fingerprints, debug certs, bank-impersonation check.

Android apps are almost always self-signed, so "self-signed" says nothing and is
not reported. What does carry signal:

  * the certificate FINGERPRINT (SHA-256 of the DER cert): the developer's
    identity. A genuine bank app is always signed with the bank's key; a
    repackaged copy can keep the package name but not the key.
  * the Android DEBUG certificate (CN=Android Debug): release apps never use it.
  * the bank ALLOWLIST (config/bank_allowlist.yaml, see docs/BANK_ALLOWLIST.md):
    package name / app name of a genuine Indian bank app + its real signing
    certificate(s). Same package or app name with a different certificate =
    impersonation.
  * certificate REUSE across samples (backend/threat_intel/cert_reuse.py).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Optional

import yaml

logger = logging.getLogger(__name__)

ALLOWLIST_PATH = Path(__file__).resolve().parents[2] / "config" / "bank_allowlist.yaml"


@dataclass
class CertInfo:
    sha256: str          # lowercase hex, no colons
    sha1: str
    subject: str
    issuer: str
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    debug: bool = False


@dataclass
class AllowlistResult:
    status: str = "not_listed"     # not_listed | genuine | impersonation | unavailable
    bank: Optional[str] = None
    detail: Optional[str] = None
    matched_by: Optional[str] = None   # package | app_name


def summarize(certs: Iterable) -> list[CertInfo]:
    """asn1crypto x509 Certificates (from androguard) -> CertInfo, deduplicated."""
    out: dict[str, CertInfo] = {}
    for c in certs:
        try:
            info = CertInfo(
                sha256=c.sha256.hex(),
                sha1=c.sha1.hex(),
                subject=c.subject.human_friendly,
                issuer=c.issuer.human_friendly,
                not_before=c.not_valid_before.isoformat(),
                not_after=c.not_valid_after.isoformat(),
            )
        except Exception as e:  # malformed cert: skip, don't crash the pipeline
            logger.warning("Could not read signing certificate: %r", e)
            continue
        info.debug = _is_debug(info)
        out.setdefault(info.sha256, info)
    return list(out.values())


def _is_debug(cert: CertInfo) -> bool:
    """The Android SDK debug keystore cert: CN=Android Debug, O=Android, C=US."""
    return "Common Name: Android Debug" in cert.subject


def normalize_fingerprint(fp: str) -> str:
    return fp.replace(":", "").replace(" ", "").strip().lower()


@lru_cache(maxsize=1)
def load_allowlist(path: str = str(ALLOWLIST_PATH)) -> tuple[dict, ...]:
    """Entries with at least one certificate fingerprint. Cached per process."""
    p = Path(path)
    if not p.exists():
        return ()
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    entries = []
    for e in data.get("banks") or []:
        certs = {normalize_fingerprint(c) for c in e.get("cert_sha256") or []}
        if not certs:
            continue  # an entry without a known certificate can't confirm or refute anything
        entries.append({
            "bank": e.get("bank", "?"),
            "packages": set(e.get("packages") or []),
            "app_names": {n.strip().lower() for n in e.get("app_names") or []},
            "certs": certs,
        })
    return tuple(entries)


def check_allowlist(package: Optional[str], app_name: Optional[str],
                    fingerprints: Iterable[str],
                    entries: Optional[tuple[dict, ...]] = None) -> AllowlistResult:
    """Compare a sample's identity against genuine bank apps."""
    entries = load_allowlist() if entries is None else entries
    if not entries:
        return AllowlistResult()
    fps = {normalize_fingerprint(f) for f in fingerprints}
    name = (app_name or "").strip().lower()
    # Package name first: it is the app's identity on the device. An app-name
    # match alone is weaker (look-alike, or an unrelated app with the same name).
    for matched_by, matches in (
        ("package", [e for e in entries if package and package in e["packages"]]),
        ("app_name", [e for e in entries if name and name in e["app_names"]]),
    ):
        for e in matches:
            if not fps:
                return AllowlistResult("unavailable", e["bank"],
                                       "Claims to be a listed bank app, but its signing "
                                       "certificate could not be read.", matched_by)
            if fps & e["certs"]:
                return AllowlistResult("genuine", e["bank"],
                                       f"Signed with {e['bank']}'s registered certificate.",
                                       matched_by)
        if matches:
            e = matches[0]
            if matched_by == "package":
                detail = (f"Uses {e['bank']}'s package name '{package}' but is NOT signed with "
                          f"{e['bank']}'s certificate (repackaged or fake app).")
            else:
                detail = (f"Uses {e['bank']}'s app name '{app_name}' with a different package "
                          f"and certificate (possible look-alike; could also be an unrelated "
                          f"app with the same name).")
            return AllowlistResult("impersonation", e["bank"], detail, matched_by)
    return AllowlistResult()
