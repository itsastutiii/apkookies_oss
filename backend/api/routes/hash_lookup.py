"""/v1/hash — fast hash-lookup endpoint (browser extension fast path).

The extension computes the SHA-256 client-side while the download is still
streaming and queries here BEFORE the file finishes writing. Must be instant and
read-only: never triggers analysis, never adds anything to the stores.

Only an exact whole-APK SHA-256 can return "benign". DEX-content hashes (if the
client can compute them) can only ever return "malicious". Whole-APK
ssdeep/tlsh fields are accepted for compatibility but not used for matching:
whole-file fuzzy hashes break on re-zipping.
"""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from backend.api.dependencies import resolve_action
from backend.hashing.content_hash import ContentHashes
from backend.hashing.exact_hash import ExactHashes
from backend.orchestration.pipeline import _lookup  # shared lookup service

router = APIRouter()


class HashLookupRequest(BaseModel):
    sha256: str
    md5: str | None = None
    ssdeep: str | None = None
    tlsh: str | None = None
    dex_sha256: str | None = None
    dex_ssdeep: str | None = None
    dex_tlsh: str | None = None
    touchpoint: str = "browser_extension"


class HashLookupResponse(BaseModel):
    known: bool
    verdict: str | None = None
    action: str                 # allow | warn | block
    matched_by: str | None = None
    cluster_id: str | None = None
    fuzzy_status: str | None = None
    verdict_source: str | None = None   # static | sandbox | analyst
    stale: bool = False                 # remembered verdict is from an older model/config


@router.post("/hash/lookup", response_model=HashLookupResponse)
async def hash_lookup(req: HashLookupRequest) -> HashLookupResponse:
    exact = ExactHashes(md5=req.md5 or "", sha256=req.sha256, size_bytes=0)
    content = (ContentHashes(dex_sha256=req.dex_sha256, dex_ssdeep=req.dex_ssdeep,
                             dex_tlsh=req.dex_tlsh)
               if req.dex_sha256 else None)
    result = _lookup.lookup(exact, content)

    if result.hit:
        # Hand-set placeholder scores for a remembered verdict (no new analysis ran),
        # chosen to land in block / warn / allow bands. To be calibrated on a labelled test set.
        score = {"malicious": 0.9, "suspicious": 0.5, "benign": 0.1}.get(result.verdict, 0.5)
        action = resolve_action(score, req.touchpoint)
        return HashLookupResponse(
            known=True, verdict=result.verdict, action=action,
            matched_by=result.matched_by, cluster_id=result.cluster_id,
            fuzzy_status=result.fuzzy_status, verdict_source=result.source,
        )
    if result.stale_verdict is not None:
        # Known, but judged by an older model/config: it needs re-analysis. Don't
        # silently allow something the old system called bad; warn until re-checked.
        action = "allow" if result.stale_verdict == "benign" else "warn"
        return HashLookupResponse(known=False, verdict=result.stale_verdict, action=action,
                                  stale=True, fuzzy_status=result.fuzzy_status)
    # Unknown -> tell the client to allow-but-submit for full analysis.
    # (Conservative clients may choose to warn on unknown; that's client policy.)
    return HashLookupResponse(known=False, action="allow", cluster_id=result.cluster_id,
                              fuzzy_status=result.fuzzy_status)
