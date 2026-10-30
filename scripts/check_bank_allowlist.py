"""Validate config/bank_allowlist.yaml before committing (see docs/BANK_ALLOWLIST.md).

    python scripts/check_bank_allowlist.py [path]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "config" / "bank_allowlist.yaml"
_HEX64 = re.compile(r"[0-9a-f]{64}")


def check(path: Path) -> list[str]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    banks = data.get("banks")
    if banks is None:
        return ["top-level key 'banks' is missing"]
    if not isinstance(banks, list):
        return ["'banks' must be a list"]
    problems: list[str] = []
    owner: dict[str, str] = {}
    for i, e in enumerate(banks, start=1):
        where = f"entry {i} ({e.get('bank', '?')})"
        for key in ("bank", "cert_sha256", "source", "collected_by"):
            if not e.get(key):
                problems.append(f"{where}: missing '{key}'")
        if not (e.get("packages") or e.get("app_names")):
            problems.append(f"{where}: needs 'packages' and/or 'app_names'")
        for fp in e.get("cert_sha256") or []:
            norm = str(fp).replace(":", "").replace(" ", "").lower()
            if not _HEX64.fullmatch(norm):
                problems.append(f"{where}: fingerprint {fp!r} is not 64 hex characters")
        for pkg in e.get("packages") or []:
            if pkg in owner and owner[pkg] != e.get("bank"):
                problems.append(f"{where}: package {pkg} is also listed under {owner[pkg]}")
            owner[pkg] = e.get("bank")
    return problems


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT
    problems = check(path)
    if problems:
        print("NOT OK:\n  " + "\n  ".join(problems))
        raise SystemExit(1)
    print(f"OK ({len(yaml.safe_load(path.read_text(encoding='utf-8')).get('banks') or [])} entries)")


if __name__ == "__main__":
    main()
