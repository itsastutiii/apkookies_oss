"""Persistence with an ephemeral-first policy.

Rule (from the brief): raw samples/artifacts are wiped post-analysis; ONLY
hashes, IOCs, and feature vectors persist. This module is the single gate for
what's allowed to be stored long-term.

MVP: in-memory + JSON-on-disk report store. TODO: swap for Postgres (reports,
IOCs) + Redis (hash cache) + object store (short-TTL artifacts).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from config.settings import get_settings
from schemas.report import Report

# Fields that may NEVER be persisted long-term (enforced by policy, not storage).
FORBIDDEN_PERSISTENT = {"raw_apk_bytes", "raw_html_bytes", "pcap_raw"}


class ReportStore:
    """MVP JSON report store. TODO: replace with a real DB-backed repository."""

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = root or (get_settings().artifact_store_path / "reports")
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, report: Report) -> None:
        path = self.root / f"{report.report_id}.json"
        path.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    def get(self, report_id: str) -> Optional[Report]:
        path = self.root / f"{report_id}.json"
        if not path.exists():
            return None
        return Report.model_validate(json.loads(path.read_text(encoding="utf-8")))

    def list_ids(self) -> list[str]:
        return [p.stem for p in self.root.glob("*.json")]


_store: Optional[ReportStore] = None


def report_store() -> ReportStore:
    global _store
    if _store is None:
        _store = ReportStore()
    return _store
