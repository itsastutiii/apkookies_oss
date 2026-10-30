"""IOC consolidation + network-traffic C2/exfil analysis.

Merges statically-extracted IOCs (static_analysis/ioc_extraction) with
dynamically-observed network indicators (sandbox), enriches via external feeds
(threatfox), and flags C2 / exfiltration. Produces the report's threat_intel
block.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from backend.sandbox.network_capture import NetworkIndicator
from backend.static_analysis.ioc_extraction import IOCReport


@dataclass
class ConsolidatedIOC:
    type: str
    value: str
    source: str                      # static|dynamic|both
    is_c2: bool = False
    is_exfil: bool = False
    is_known_service: bool = False
    is_private: bool = False
    enrichment: dict | None = None
    telegram_c2_live: bool | None = None


@dataclass
class IntelResult:
    iocs: list[ConsolidatedIOC] = field(default_factory=list)


def consolidate(static_iocs: IOCReport,
                network: list[NetworkIndicator] | None = None) -> IntelResult:
    result = IntelResult()
    index: dict[tuple[str, str], ConsolidatedIOC] = {}

    for ioc in static_iocs.iocs:
        c = ConsolidatedIOC(
            type=ioc.type,
            value=ioc.value,
            source="static",
            is_known_service=getattr(ioc, "is_known_service", False),
            is_private=getattr(ioc, "is_private", False),
        )
        index[(ioc.type, ioc.value.lower())] = c
        result.iocs.append(c)

    for ind in network or []:
        key_type = {"dns": "domain", "http": "url", "https": "url", "tcp": "ip"}.get(ind.kind, "domain")
        key = (key_type, ind.indicator.lower())
        if key in index:
            existing = index[key]
            existing.source = "both"
            existing.is_c2 = existing.is_c2 or ind.is_c2
            existing.is_exfil = existing.is_exfil or ind.is_exfil
        else:
            c = ConsolidatedIOC(
                type=key_type, value=ind.indicator, source="dynamic",
                is_c2=ind.is_c2, is_exfil=ind.is_exfil,
            )
            index[key] = c
            result.iocs.append(c)

    return result
