"""Fill a running backend with demo reports, for the SOC portal. No real APKs.

Submits archives built in memory from the committed test fixtures
(tests/fixtures/dex/*.dex: tiny DEX files compiled from source, never executed)
to POST /v1/submit/apk, exactly as a touchpoint would:

  1. suspicious.apk : accessibility + overlay + SMS code   -> suspicious, warn (R002, stage 3)
  2. benign.apk     : a harmless app with decoy strings     -> low score
  3. repacked.apk   : suspicious.apk re-zipped with an extra file: a different
                      file hash, the same DEX code. Only "malicious" verdicts
                      spread to look-alikes, so this one is analysed in full.

    uvicorn backend.api.main:app --port 8000          # in one terminal
    python scripts/seed_demo_reports.py               # in another
    python scripts/seed_demo_reports.py --api http://localhost:8000
"""
from __future__ import annotations

import argparse
import io
import sys
import zipfile
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "dex"
MANIFEST = b"\x03\x00\x08\x00" + b"\x00" * 64   # deliberately unreadable manifest


def archive(dex: bytes, extra: bytes = b"") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED if extra else zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", MANIFEST)
        zf.writestr("classes.dex", dex)
        if extra:
            zf.writestr("assets/repack.txt", extra)
    return buf.getvalue()


def samples() -> list[tuple[str, bytes]]:
    bad, good = (FIX / "suspicious.dex").read_bytes(), (FIX / "benign.dex").read_bytes()
    return [("suspicious.apk", archive(bad)), ("benign.apk", archive(good)),
            ("repacked.apk", archive(bad, extra=b"repackaged by the demo"))]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--api", default="http://localhost:8000")
    args = ap.parse_args(argv)
    with httpx.Client(base_url=args.api.rstrip("/"), timeout=300) as client:
        try:
            client.get("/docs").raise_for_status()
        except httpx.HTTPError:
            print(f"No backend at {args.api}. Start it first: uvicorn backend.api.main:app --port 8000")
            return 1
        for name, data in samples():
            r = client.post("/v1/submit/apk", data={"touchpoint": "soc_portal"},
                            files={"file": (name, data, "application/vnd.android.package-archive")})
            r.raise_for_status()
            body = r.json()
            rep = body["report"]
            via = rep["hashes"].get("inherited_verdict_from") or "full analysis"
            print(f"{name:15s} -> {rep['verdict']['label']:10s} score {rep['risk']['score']:.2f} "
                  f"action {body['action']:5s} ({via})  report {rep['report_id']}")
    print("Open the portal (npm run dev in clients/soc_portal) and pick a report.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
