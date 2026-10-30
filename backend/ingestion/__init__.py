"""Ingestion layer: URL resolution, content detection, sample acquisition."""
from backend.ingestion.acquisition import AcquiredSample, from_upload, from_url, wipe  # noqa: F401
from backend.ingestion.file_signature import ContentKind, detect_bytes, detect_file  # noqa: F401
from backend.ingestion.url_resolver import UrlResolution, resolve  # noqa: F401
