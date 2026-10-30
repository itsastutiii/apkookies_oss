"""Persistent verdict store (SQLite) with provenance, analyst overrides and an audit log.

One row per exact whole-APK SHA-256. A row records the verdict, where it came
from (static analysis, sandbox re-score, or an analyst), the DEX-content hashes
needed to rebuild variant matching after a restart, the signing-certificate
fingerprints (for certificate reuse), and the provenance of the system that
produced it (backend/common/provenance.py).

Lifecycle rules:
  * An analyst verdict is only changed by another analyst action. Re-analysis
    (e.g. a forced sandbox run) never overwrites it.
  * A machine verdict whose provenance fingerprint differs from the running
    system (retrained model, changed scoring config) is STALE: it is not
    returned as a known verdict and not inherited by look-alikes; the sample
    is re-analysed the next time it is seen.
  * "Clear" keeps the row for the audit trail but takes it out of every lookup.
  * Every analyst action, and every automatic replacement of a stale verdict,
    is appended to `audit`; rows are never deleted from it.

Raw samples are never stored here (see common/storage.py's policy).
"""
from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from backend.common import provenance

VERDICTS = ("benign", "suspicious", "malicious")
SOURCES = ("static", "sandbox", "analyst")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS verdicts (
    sha256        TEXT PRIMARY KEY,
    verdict       TEXT NOT NULL,
    source        TEXT NOT NULL,
    dex_sha256    TEXT,
    dex_ssdeep    TEXT,
    dex_tlsh      TEXT,
    cluster_id    TEXT,
    family        TEXT,
    fingerprints  TEXT NOT NULL DEFAULT '[]',
    provenance    TEXT NOT NULL,
    cleared       INTEGER NOT NULL DEFAULT 0,
    updated_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    old_verdict TEXT,
    new_verdict TEXT,
    reason      TEXT
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class StoredVerdict:
    sha256: str
    verdict: str
    source: str
    provenance: dict
    dex_sha256: Optional[str] = None
    dex_ssdeep: Optional[str] = None
    dex_tlsh: Optional[str] = None
    cluster_id: Optional[str] = None
    family: Optional[str] = None
    fingerprints: list[str] = field(default_factory=list)
    cleared: bool = False
    updated_at: str = ""

    def is_stale(self, current_fingerprint: str) -> bool:
        # Analyst decisions are human judgements, not model outputs: never stale.
        return self.source != "analyst" and self.provenance.get("fingerprint") != current_fingerprint


class VerdictStore:
    """SQLite-backed; `path=":memory:"` for tests and demos."""

    def __init__(self, path: str | Path = ":memory:",
                 current_provenance: Optional[dict] = None) -> None:
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock, self._db:
            self._db.executescript(_SCHEMA)
        self._current = current_provenance

    # -- provenance -------------------------------------------------------
    @property
    def current_fingerprint(self) -> str:
        return self.current_provenance()["fingerprint"]

    def current_provenance(self) -> dict:
        if self._current is None:
            self._current = provenance.current()
        return self._current

    def _stamp(self, source: str) -> dict:
        return {**self.current_provenance(), "source": source, "recorded_at": _now()}

    # -- reads ------------------------------------------------------------
    def get(self, sha256: str, include_cleared: bool = False) -> Optional[StoredVerdict]:
        with self._lock:
            row = self._db.execute("SELECT * FROM verdicts WHERE sha256 = ?", (sha256,)).fetchone()
        if row is None:
            return None
        v = _from_row(row)
        return v if include_cleared or not v.cleared else None

    def active(self) -> Iterator[StoredVerdict]:
        """Every non-cleared verdict, oldest first (stale ones included)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM verdicts WHERE cleared = 0 ORDER BY rowid").fetchall()
        return (_from_row(r) for r in rows)

    def stale(self) -> list[StoredVerdict]:
        fp = self.current_fingerprint
        return [v for v in self.active() if v.is_stale(fp)]

    def history(self, sha256: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM audit WHERE sha256 = ? ORDER BY id",
                                    (sha256,)).fetchall()
        return [dict(r) for r in rows]

    # -- writes -----------------------------------------------------------
    def record(self, sha256: str, verdict: str, source: str, *,
               dex_sha256: Optional[str] = None, dex_ssdeep: Optional[str] = None,
               dex_tlsh: Optional[str] = None, cluster_id: Optional[str] = None,
               family: Optional[str] = None,
               fingerprints: Optional[list[str]] = None) -> bool:
        """Store a machine verdict (static or sandbox). Returns False, and changes
        nothing, if an analyst verdict already exists for this sample."""
        if verdict not in VERDICTS or source not in ("static", "sandbox"):
            raise ValueError(f"bad verdict/source: {verdict}/{source}")
        existing = self.get(sha256, include_cleared=True)
        if existing is not None and existing.source == "analyst" and not existing.cleared:
            return False
        with self._lock, self._db:
            if (existing is not None and not existing.cleared
                    and existing.is_stale(self.current_fingerprint)):
                self._audit("system", "recheck", sha256, existing.verdict, verdict,
                            "stale verdict re-checked with the current model/config "
                            f"(was {existing.provenance.get('fingerprint')})")
            self._db.execute(
                """INSERT OR REPLACE INTO verdicts
                   (sha256, verdict, source, dex_sha256, dex_ssdeep, dex_tlsh, cluster_id,
                    family, fingerprints, provenance, cleared, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)""",
                (sha256, verdict, source, dex_sha256, dex_ssdeep, dex_tlsh, cluster_id, family,
                 json.dumps(fingerprints or []), json.dumps(self._stamp(source)), _now()))
        return True

    def set_cluster(self, sha256: str, cluster_id: Optional[str]) -> None:
        with self._lock, self._db:
            self._db.execute("UPDATE verdicts SET cluster_id = ? WHERE sha256 = ?",
                             (cluster_id, sha256))

    def override(self, sha256: str, verdict: str, analyst: str, reason: str) -> StoredVerdict:
        """Analyst sets the verdict for this exact file. A benign override never spreads
        to look-alikes: inheritance only ever carries malicious verdicts (lookup.py)."""
        if verdict not in VERDICTS:
            raise ValueError(f"verdict must be one of {VERDICTS}")
        _require(analyst, reason)
        existing = self.get(sha256, include_cleared=True)
        with self._lock, self._db:
            self._audit(analyst, "override", sha256,
                        existing.verdict if existing and not existing.cleared else None,
                        verdict, reason)
            if existing is None:
                self._db.execute(
                    """INSERT INTO verdicts (sha256, verdict, source, provenance, updated_at)
                       VALUES (?, ?, 'analyst', ?, ?)""",
                    (sha256, verdict, json.dumps(self._analyst_stamp(analyst, reason)), _now()))
            else:
                self._db.execute(
                    """UPDATE verdicts SET verdict = ?, source = 'analyst', provenance = ?,
                       cleared = 0, updated_at = ? WHERE sha256 = ?""",
                    (verdict, json.dumps(self._analyst_stamp(analyst, reason)), _now(), sha256))
        return self.get(sha256)  # type: ignore[return-value]

    def clear(self, sha256: str, analyst: str, reason: str) -> bool:
        """Take a verdict out of every lookup (the sample is re-analysed next time).
        The row stays, marked cleared, for the audit trail."""
        _require(analyst, reason)
        existing = self.get(sha256)
        if existing is None:
            return False
        with self._lock, self._db:
            self._audit(analyst, "clear", sha256, existing.verdict, None, reason)
            self._db.execute("UPDATE verdicts SET cleared = 1, updated_at = ? WHERE sha256 = ?",
                             (_now(), sha256))
        return True

    def _analyst_stamp(self, analyst: str, reason: str) -> dict:
        return {**self._stamp("analyst"), "analyst": analyst, "reason": reason}

    def _audit(self, actor: str, action: str, sha256: str, old: Optional[str],
               new: Optional[str], reason: str) -> None:
        # Caller holds the lock and the transaction.
        self._db.execute(
            "INSERT INTO audit (at, actor, action, sha256, old_verdict, new_verdict, reason) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)", (_now(), actor, action, sha256, old, new, reason))


def _require(analyst: str, reason: str) -> None:
    if not (analyst or "").strip() or not (reason or "").strip():
        raise ValueError("analyst and reason are required for the audit log")


def _from_row(row: sqlite3.Row) -> StoredVerdict:
    return StoredVerdict(
        sha256=row["sha256"], verdict=row["verdict"], source=row["source"],
        provenance=json.loads(row["provenance"]), dex_sha256=row["dex_sha256"],
        dex_ssdeep=row["dex_ssdeep"], dex_tlsh=row["dex_tlsh"], cluster_id=row["cluster_id"],
        family=row["family"], fingerprints=json.loads(row["fingerprints"]),
        cleared=bool(row["cleared"]), updated_at=row["updated_at"],
    )
