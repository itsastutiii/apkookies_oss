"""Canonical feature extraction for the scoring subsystem.

The same deterministic extractor is used by training scripts and live inference.
It deliberately consumes the existing StaticBundle instead of introducing a second
input schema.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from backend.static_analysis import StaticBundle


@dataclass(frozen=True)
class ScoringFeatures:
    permissions: tuple[str, ...]
    category: str | None
    api_counts: dict[str, int]
    obfuscation_count: int
    anti_analysis_count: int
    suspicious_api_count: int
    self_signed: int
    debug_signed: int
    exported_component_count: int
    ioc_counts: dict[str, int]


def build_features(bundle: StaticBundle, category: str | None = None) -> ScoringFeatures:
    manifest = bundle.structural.manifest
    effective_category = category or manifest.declared_category
    api_counts: dict[str, int] = {}
    own = bundle.api_usage.own()           # third-party library call sites don't count
    for obs in own:
        key = obs.category.value
        api_counts[key] = api_counts.get(key, 0) + 1
    ioc_counts: dict[str, int] = {}
    for ioc in bundle.iocs.iocs:
        ioc_counts[ioc.type] = ioc_counts.get(ioc.type, 0) + 1
    exported = sum(1 for c in manifest.components if c.exported)
    return ScoringFeatures(
        permissions=tuple(sorted(set(manifest.permissions))),
        category=effective_category,
        api_counts=api_counts,
        obfuscation_count=len(bundle.code_intel.obfuscation),
        anti_analysis_count=len(bundle.anti_analysis.findings),
        suspicious_api_count=sum(1 for o in own if o.suspicious),
        # Retired signal (nearly every Android app is self-signed). The slot stays at 0
        # because the trained model expects 19 scalars; it has no splits on it.
        self_signed=0,
        debug_signed=int(bool(bundle.structural.signing.debug_signed)),
        exported_component_count=exported,
        ioc_counts=ioc_counts,
    )


SENSITIVE_PERMISSIONS = frozenset({
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS",
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.RECORD_AUDIO",
    "android.permission.READ_CONTACTS", "android.permission.READ_CALL_LOG",
    "android.permission.CALL_PHONE",
})


def to_scalar_features(features: ScoringFeatures):
    """The 19 scalar model inputs. Used by live scoring AND by the dataset builder
    (ml/data/build_androzoo_dataset.py), so training and inference can't drift."""
    from backend.scoring.aggregator import ScalarFeatures

    api, ioc = features.api_counts, features.ioc_counts
    return ScalarFeatures(
        obfuscation_count=features.obfuscation_count,
        anti_analysis_count=features.anti_analysis_count,
        suspicious_api_count=features.suspicious_api_count,
        self_signed=bool(features.self_signed),
        debug_signed=bool(features.debug_signed),
        exported_component_count=features.exported_component_count,
        sms_api_count=api.get("sms", 0),
        accessibility_api_count=api.get("accessibility", 0),
        overlay_api_count=api.get("overlay", 0),
        network_api_count=api.get("network", 0),
        telephony_api_count=api.get("telephony", 0),
        webview_api_count=api.get("webview", 0),
        crypto_api_count=api.get("crypto", 0),
        telegram_token_count=ioc.get("telegram_token", 0),
        domain_count=ioc.get("domain", 0),
        ip_count=ioc.get("ip", 0),
        url_count=ioc.get("url", 0),
        permission_count=len(features.permissions),
        sensitive_permission_count=sum(1 for p in features.permissions if p in SENSITIVE_PERMISSIONS),
    )


def scalar_vector(features: ScoringFeatures) -> list[float]:
    """Stable small feature vector used by the aggregator."""
    api = features.api_counts
    ioc = features.ioc_counts
    return [
        float(features.obfuscation_count),
        float(features.anti_analysis_count),
        float(features.suspicious_api_count),
        float(features.self_signed),
        float(features.debug_signed),
        float(features.exported_component_count),
        float(api.get("sms", 0)),
        float(api.get("accessibility", 0)),
        float(api.get("overlay", 0)),
        float(api.get("network", 0)),
        float(api.get("telephony", 0)),
        float(api.get("webview", 0)),
        float(api.get("crypto", 0)),
        float(ioc.get("telegram_token", 0)),
        float(ioc.get("domain", 0)),
        float(ioc.get("ip", 0)),
        float(ioc.get("url", 0)),
    ]


def permission_vector(permissions: Iterable[str], vocabulary: list[str]) -> list[float]:
    present = set(permissions)
    return [1.0 if p in present else 0.0 for p in vocabulary]
