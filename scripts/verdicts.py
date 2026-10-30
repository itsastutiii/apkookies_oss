"""Inspect and manage remembered verdicts from the command line (same rules as /v1/verdicts).

    python scripts/verdicts.py stale                       # verdicts made by an older model/config
    python scripts/verdicts.py show <sha256>               # stored verdict, provenance, audit history
    python scripts/verdicts.py override <sha256> malicious --analyst NAME --reason "..."
    python scripts/verdicts.py clear <sha256> --analyst NAME --reason "..."

Uses VERDICT_DB_PATH from .env (default ./.artifacts/verdicts.sqlite3). Stale
verdicts are re-checked automatically the next time their file is submitted;
`stale` shows how many are waiting after a retrain.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.hashing.lookup import HashLookupService  # noqa: E402
from backend.hashing.verdict_store import VerdictStore  # noqa: E402
from config.settings import get_settings  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", default=None, help="override VERDICT_DB_PATH")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("stale")
    show = sub.add_parser("show")
    show.add_argument("sha256")
    ov = sub.add_parser("override")
    ov.add_argument("sha256")
    ov.add_argument("verdict", choices=["benign", "suspicious", "malicious"])
    clr = sub.add_parser("clear")
    clr.add_argument("sha256")
    for p in (ov, clr):
        p.add_argument("--analyst", required=True)
        p.add_argument("--reason", required=True)
    args = ap.parse_args(argv)

    svc = HashLookupService(store=VerdictStore(args.db or get_settings().verdict_db_path))
    sha = getattr(args, "sha256", "").lower()
    if args.cmd == "stale":
        rows = svc.store.stale()
        print(f"{len(rows)} stale verdict(s); current fingerprint {svc.store.current_fingerprint}")
        for r in rows:
            print(f"  {r.sha256}  {r.verdict:<10} {r.source:<8} made by {r.provenance.get('fingerprint')}")
        return 0
    if args.cmd == "override":
        svc.override(sha, args.verdict, args.analyst, args.reason)
    elif args.cmd == "clear" and not svc.clear(sha, args.analyst, args.reason):
        print("no stored verdict for this sha256")
        return 1
    row = svc.store.get(sha, include_cleared=True)
    print(json.dumps({"stored": asdict(row) if row else None,
                      "stale": row.is_stale(svc.store.current_fingerprint) if row else None,
                      "history": svc.store.history(sha)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
