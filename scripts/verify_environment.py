"""Fail-fast environment verification for a clean checkout."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import importlib
import platform
import sys

REQUIRED = ["numpy", "pandas", "sklearn", "joblib", "xgboost", "torch", "androguard"]

print(f"Python: {sys.version.split()[0]} ({platform.machine()})")
failed = []
for name in REQUIRED:
    try:
        mod = importlib.import_module(name)
        print(f"OK  {name}: {getattr(mod, '__version__', 'installed')}")
    except Exception as exc:
        failed.append((name, repr(exc)))
        print(f"FAIL {name}: {exc}")
if failed:
    raise SystemExit(1)
print("Environment OK")
