"""ThreatFox feed enrichment (abuse.ch).

Enriches extracted IOCs against the live ThreatFox IOC database (malware family,
confidence, first/last seen). Requires THREATFOX_API_KEY. Network egress here
should be allow-listed; results are cached to respect rate limits.

TODO: add response caching + backoff; map ThreatFox malware labels to our
family taxonomy.
"""
from __future__ import annotations

from dataclasses import dataclass

import httpx

from config.settings import get_settings

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"


@dataclass
class EnrichmentResult:
    found: bool
    malware: str | None = None
    confidence: int | None = None
    raw: dict | None = None


async def enrich_ioc(value: str) -> EnrichmentResult:
    """Query ThreatFox for a single IOC (domain/ip/url/hash)."""
    settings = get_settings()
    if settings.threatfox_api_key in ("", "CHANGE_ME"):
        # No key configured -> skip gracefully (offline/dev mode).
        return EnrichmentResult(found=False)

    payload = {"query": "search_ioc", "search_term": value}
    headers = {"Auth-Key": settings.threatfox_api_key}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(THREATFOX_API, json=payload, headers=headers)
            data = resp.json()
    except (httpx.HTTPError, ValueError):  # network/parse failure -> non-fatal
        return EnrichmentResult(found=False)

    rows = data.get("data") or []
    if not rows:
        return EnrichmentResult(found=False, raw=data)
    row = rows[0]
    return EnrichmentResult(
        found=True,
        malware=row.get("malware_printable"),
        confidence=row.get("confidence_level"),
        raw=row,
    )
