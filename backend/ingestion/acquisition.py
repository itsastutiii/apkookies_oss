"""Sample acquisition + ephemeral handling.

Normalizes the two input types (uploaded APK bytes, or a URL that resolves to an
APK/HTML) into an `AcquiredSample`. Raw bytes are written to an ephemeral store
and MUST be wiped post-analysis (only hashes/IOCs/feature vectors persist).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from backend.ingestion.file_signature import ContentKind, detect_bytes
from backend.ingestion.url_resolver import UrlResolution, resolve
from config.settings import get_settings


@dataclass
class AcquiredSample:
    sample_id: str
    kind: ContentKind
    data: bytes
    origin_url: Optional[str] = None
    filename: Optional[str] = None
    url_resolution: Optional[UrlResolution] = None
    ephemeral_path: Optional[Path] = None


def _ephemeral_path(sample_id: str) -> Path:
    root = get_settings().artifact_store_path
    root.mkdir(parents=True, exist_ok=True)
    return root / f"{sample_id}.bin"


def from_upload(data: bytes, filename: Optional[str] = None) -> AcquiredSample:
    sample_id = uuid.uuid4().hex
    kind = detect_bytes(data)
    path = _ephemeral_path(sample_id)
    path.write_bytes(data)
    return AcquiredSample(
        sample_id=sample_id, kind=kind, data=data, filename=filename, ephemeral_path=path
    )


async def from_url(url: str) -> AcquiredSample:
    """Resolve a URL, then classify the final content by signature."""
    resolution = await resolve(url)
    body = resolution.mobile.body or resolution.plain.body
    sample_id = uuid.uuid4().hex
    kind = detect_bytes(body) if body else ContentKind.html
    path = _ephemeral_path(sample_id)
    if body:
        path.write_bytes(body)
    return AcquiredSample(
        sample_id=sample_id,
        kind=kind,
        data=body,
        origin_url=url,
        url_resolution=resolution,
        ephemeral_path=path,
    )


def wipe(sample: AcquiredSample) -> None:
    """Delete raw bytes per the ephemeral-storage policy."""
    if sample.ephemeral_path and sample.ephemeral_path.exists():
        sample.ephemeral_path.unlink()
