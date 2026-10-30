"""STIX 2.1 export of report findings for sharing/ingestion by other tools.

Builds a STIX bundle (Indicator, Malware, AttackPattern SDOs + relationships)
from a Report. Uses the `stix2` library when available; otherwise emits a
minimal hand-rolled bundle dict so export never hard-fails.

TODO: full mapping (Infrastructure, Observed-Data, kill-chain phases).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

try:  # optional
    import stix2  # type: ignore
    _HAS_STIX2 = True
except ImportError:  # pragma: no cover
    _HAS_STIX2 = False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def to_stix_bundle(report) -> dict:
    """Return a STIX 2.1 bundle (as dict) for the given schemas.Report."""
    if _HAS_STIX2:
        return _build_with_stix2(report)
    return _build_minimal(report)


def _build_minimal(report) -> dict:
    objects: list[dict] = []
    for ioc in report.threat_intel.iocs:
        pattern = _pattern_for(ioc.type, ioc.value)
        if not pattern:
            continue
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": _now(),
            "modified": _now(),
            "name": f"{ioc.type}:{ioc.value}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": _now(),
        })
    if report.threat_intel.family:
        objects.append({
            "type": "malware",
            "spec_version": "2.1",
            "id": f"malware--{uuid.uuid4()}",
            "created": _now(),
            "modified": _now(),
            "name": report.threat_intel.family,
            "is_family": True,
        })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def _build_with_stix2(report) -> dict:  # pragma: no cover - needs stix2
    objects = []
    for ioc in report.threat_intel.iocs:
        pattern = _pattern_for(ioc.type, ioc.value)
        if pattern:
            objects.append(stix2.Indicator(name=f"{ioc.type}:{ioc.value}", pattern=pattern,
                                           pattern_type="stix"))
    if report.threat_intel.family:
        objects.append(stix2.Malware(name=report.threat_intel.family, is_family=True))
    bundle = stix2.Bundle(objects=objects)
    return bundle.serialize(pretty=False) and dict(bundle)


def _pattern_for(ioc_type: str, value: str) -> str | None:
    v = value.replace("'", "\\'")
    return {
        "domain": f"[domain-name:value = '{v}']",
        "ip": f"[ipv4-addr:value = '{v}']",
        "url": f"[url:value = '{v}']",
        "hash": f"[file:hashes.'SHA-256' = '{v}']",
    }.get(ioc_type)
