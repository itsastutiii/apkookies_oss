"""URL ingestion: resolve full redirect chain with cloaking detection.

Strategy:
  * Fetch TWICE in parallel — once with a spoofed mobile/WhatsApp User-Agent
    (what a victim's device sees) and once with a "plain" UA. Divergence between
    the two final destinations/bodies is a strong cloaking signal (server serves
    the payload only to the targeted client).
  * Follow redirects manually so the entire hop chain (including JS/meta-refresh
    hints) is captured for the report and IOC extraction.
  * Determine real content by file signature downstream — headers are untrusted.

Uses httpx (already a core dependency). Network egress here should itself be
sandbox/proxy-routed in production. TODO: route through the analysis proxy.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional

import httpx

# Realistic Android WhatsApp in-app browser UA (what forwarded links open with).
WHATSAPP_ANDROID_UA = (
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Mobile Safari/537.36"
)
PLAIN_UA = "python-httpx/analysis-plain"

MAX_HOPS = 15
FETCH_TIMEOUT = 15.0


@dataclass
class Hop:
    url: str
    status: int
    location: Optional[str] = None
    via: str = "http_redirect"  # http_redirect | meta_refresh | js_redirect


@dataclass
class FetchResult:
    profile: str                       # "whatsapp_android" | "plain"
    final_url: str
    hops: list[Hop] = field(default_factory=list)
    status: int = 0
    declared_content_type: Optional[str] = None
    body: bytes = b""


@dataclass
class UrlResolution:
    input_url: str
    mobile: FetchResult
    plain: FetchResult
    cloaking_suspected: bool = False
    redirect_domains: list[str] = field(default_factory=list)


async def _fetch(client: httpx.AsyncClient, url: str, profile: str, ua: str) -> FetchResult:
    hops: list[Hop] = []
    current = url
    result = FetchResult(profile=profile, final_url=url)
    for _ in range(MAX_HOPS):
        resp = await client.get(current, headers={"User-Agent": ua})
        loc = resp.headers.get("location")
        hops.append(Hop(url=current, status=resp.status_code, location=loc))
        if resp.is_redirect and loc:
            current = str(resp.next_request.url) if resp.next_request else loc
            continue
        result.final_url = current
        result.status = resp.status_code
        result.declared_content_type = resp.headers.get("content-type")
        result.body = resp.content
        break
    result.hops = hops
    # TODO: detect meta-refresh / JS `window.location` redirects in HTML bodies.
    return result


async def resolve(url: str) -> UrlResolution:
    """Resolve a URL under both UA profiles and flag cloaking."""
    # follow_redirects=False so we record each hop ourselves.
    async with httpx.AsyncClient(follow_redirects=False, timeout=FETCH_TIMEOUT) as client:
        mobile, plain = await asyncio.gather(
            _fetch(client, url, "whatsapp_android", WHATSAPP_ANDROID_UA),
            _fetch(client, url, "plain", PLAIN_UA),
        )

    cloaking = mobile.final_url != plain.final_url or (
        bool(mobile.body) and bool(plain.body) and mobile.body[:2048] != plain.body[:2048]
    )
    domains = _collect_domains(mobile) | _collect_domains(plain)
    return UrlResolution(
        input_url=url,
        mobile=mobile,
        plain=plain,
        cloaking_suspected=cloaking,
        redirect_domains=sorted(domains),
    )


def _collect_domains(fr: FetchResult) -> set[str]:
    domains = set()
    for hop in fr.hops:
        host = httpx.URL(hop.url).host
        if host:
            domains.add(host)
    return domains
