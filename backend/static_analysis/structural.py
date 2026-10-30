"""Structural analysis: decompile & inventory the APK.

Covers manifest (delegated), DEX inventory, resources, native libs, signing
schemes (v1/v2/v3) and signing certificates (fingerprints, debug cert, bank
allowlist check; see signing.py). Certificate parsing uses androguard.
"""
from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from backend.static_analysis import signing as cert_signing
from backend.static_analysis.manifest import ManifestFacts, parse_apk

try:  # optional
    from androguard.core.apk import APK as _APK  # type: ignore
except ImportError:  # pragma: no cover
    _APK = None


@dataclass
class SigningInfo:
    schemes: list[str] = field(default_factory=list)  # subset of v1,v2,v3
    debug_signed: bool | None = None
    issuer: str | None = None
    certificates: list[cert_signing.CertInfo] = field(default_factory=list)
    app_name: str | None = None
    allowlist: cert_signing.AllowlistResult = field(default_factory=cert_signing.AllowlistResult)

    @property
    def fingerprints(self) -> list[str]:
        return [c.sha256 for c in self.certificates]


@dataclass
class StructuralReport:
    manifest: ManifestFacts
    dex_files: list[str] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)  # lib/<abi>/*.so
    resource_files: int = 0
    assets: list[str] = field(default_factory=list)
    signing: SigningInfo = field(default_factory=SigningInfo)


def analyze(path: str | Path) -> StructuralReport:
    path = Path(path)
    manifest = parse_apk(path)
    dex, native, assets = [], [], []
    res_count = 0
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            if name.endswith(".dex"):
                dex.append(name)
            elif name.startswith("lib/") and name.endswith(".so"):
                native.append(name)
            elif name.startswith("res/"):
                res_count += 1
            elif name.startswith("assets/"):
                assets.append(name)
        signing = _detect_signing(zf, path)
    signing.allowlist = cert_signing.check_allowlist(
        manifest.package_name, signing.app_name, signing.fingerprints)
    return StructuralReport(
        manifest=manifest,
        dex_files=sorted(dex),
        native_libs=sorted(native),
        resource_files=res_count,
        assets=sorted(assets),
        signing=signing,
    )


def _detect_signing(zf: zipfile.ZipFile, path: Path) -> SigningInfo:
    names = zf.namelist()
    schemes: list[str] = []
    # v1 (JAR signing): META-INF/*.RSA|DSA|EC + MANIFEST.MF
    if any(n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC")) for n in names):
        schemes.append("v1")
    # v2/v3 live in the APK Signing Block (not a file entry) -> need real parse.
    if _APK is not None:
        try:
            apk = _APK(str(path))
            if apk.is_signed_v2():
                schemes.append("v2")
            if apk.is_signed_v3():
                schemes.append("v3")
            certs = cert_signing.summarize(apk.get_certificates() or [])
        except Exception:  # unreadable signing block: report what we have
            return SigningInfo(schemes=schemes)
        try:
            app_name = apk.get_app_name() or None
        except Exception:
            app_name = None
        return SigningInfo(
            schemes=schemes,
            debug_signed=any(c.debug for c in certs) if certs else None,
            issuer=certs[0].issuer if certs else None,
            certificates=certs,
            app_name=app_name,
        )
    # TODO: parse APK Signing Block manually to detect v2/v3 without androguard.
    return SigningInfo(schemes=schemes)
