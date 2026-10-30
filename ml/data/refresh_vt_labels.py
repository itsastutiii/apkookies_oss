"""Optional: refresh the VirusTotal labels of the recent APKs in the committed selection.

Why: AndroZoo's `vt_detection` comes from one VirusTotal scan, usually 30-44
days after AndroZoo added the APK, and is never refreshed. Detection counts keep
rising for months, so labels of 2024-2026 APKs are the least settled. This
script asks VirusTotal for the CURRENT report of each of those hashes and writes
the refreshed counts to a separate file. It changes nothing else; whether
training uses the refreshed labels is up to whoever trains the models.

  * Lookup by hash only: GET /api/v3/files/{sha256}. Nothing is ever uploaded,
    and no APK is needed or touched, so it can run on any machine.
  * The key is personal to whoever runs it: read only from the VT_API_KEY
    environment variable, never from the command line, never printed or logged
    (errors are recorded as error types only).
  * Free public API limits: at most 4 requests a minute (one every 15 s) and
    500 a day (UTC). Every request counts, including 404s and errors. On reaching
    the daily cap it stops; run the same command the next day to continue.
    VirusTotal's free API is for non-commercial use, like AndroZoo.
  * Resumable: one CSV row is appended (and flushed) per hash; hashes already in
    the output are skipped. --retry-errors re-asks for rows that failed.

    export VT_API_KEY   # set it with: read -rs VT_API_KEY && export VT_API_KEY
    python ml/data/refresh_vt_labels.py                      # 2024 on, ~1,330 hashes, ~3 days
    python ml/data/refresh_vt_labels.py --from-year 2025 --limit 50

Output (default ml/data/androzoo/vt_refreshed.csv; committable, hashes and counts only):
  sha256, AndroZoo label/detections/scan date, VirusTotal's current malicious /
  suspicious / undetected / harmless counts and last-analysis date, the label the
  same thresholds would give today, and status (ok | not_found | error:<type>).
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

ROOT = Path(__file__).resolve().parents[2]
VT_FILE_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
MIN_INTERVAL_SECONDS = 15.0      # free tier: 4 requests/minute
DAILY_LIMIT = 500                # free tier: 500 requests/day
COLUMNS = ["sha256", "androzoo_label", "androzoo_vt_detection", "androzoo_vt_scan_date", "added",
           "vt_malicious", "vt_suspicious", "vt_undetected", "vt_harmless", "vt_last_analysis_date",
           "refreshed_label", "status", "fetched_at"]

log = logging.getLogger("vt_refresh")


class DailyLimitReached(Exception):
    pass


class RateLimiter:
    """At most one request per `interval` seconds and `daily` requests per UTC day."""

    def __init__(self, interval: float, daily: int, used_today: int,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.interval, self.daily, self.used_today = interval, daily, used_today
        self._clock, self._sleep = clock, sleep
        self._last: Optional[float] = None

    def wait(self) -> None:
        if self.used_today >= self.daily:
            raise DailyLimitReached()
        if self._last is not None:
            delay = self._last + self.interval - self._clock()
            if delay > 0:
                self._sleep(delay)
        self._last = self._clock()
        self.used_today += 1


def label_for(malicious: int, benign_max: int, malicious_min: int) -> str:
    if malicious <= benign_max:
        return "benign"
    if malicious >= malicious_min:
        return "malicious"
    return "grey_zone"


def lookup(client, key: str, sha256: str, limiter: RateLimiter, retries: int = 3) -> dict:
    """One hash lookup. Returns the VirusTotal fields plus `status`. Never lets an
    exception (which could carry request details) escape."""
    for attempt in range(retries):
        limiter.wait()
        try:
            r = client.get(VT_FILE_URL.format(sha256=sha256), headers={"x-apikey": key})
        except Exception as e:  # noqa: BLE001
            status = f"error:{type(e).__name__}"
        else:
            if r.status_code == 200:
                attrs = r.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                ts = attrs.get("last_analysis_date")
                return {"status": "ok",
                        "vt_malicious": int(stats.get("malicious", 0)),
                        "vt_suspicious": int(stats.get("suspicious", 0)),
                        "vt_undetected": int(stats.get("undetected", 0)),
                        "vt_harmless": int(stats.get("harmless", 0)),
                        "vt_last_analysis_date": (datetime.fromtimestamp(ts, timezone.utc).date().isoformat()
                                                  if ts else "")}
            if r.status_code == 404:
                return {"status": "not_found"}
            if r.status_code == 429:
                # Per-minute burst or daily quota. Either way: back off; the daily
                # counter stops the run once the day's requests are used up.
                status = "error:http_429"
                time.sleep(60)
                continue
            if r.status_code in (401, 403):
                raise SystemExit(f"VirusTotal rejected the key (HTTP {r.status_code}). "
                                 "Check VT_API_KEY; nothing else was changed.")
            status = f"error:http_{r.status_code}"
        if attempt < retries - 1:
            time.sleep(5 * 2 ** attempt)
    return {"status": status}


def _read_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def refresh(selection: Path, out: Path, *, from_year: int, limit: Optional[int], retry_errors: bool,
            benign_max: int, malicious_min: int, client=None, limiter: Optional[RateLimiter] = None) -> dict:
    key = os.environ.get("VT_API_KEY", "").strip()
    if not key:
        raise SystemExit("VT_API_KEY is not set. Set it in this shell (read -rs VT_API_KEY && "
                         "export VT_API_KEY); it is never accepted on the command line.")
    for name in ("httpx", "httpcore"):                  # never log request headers
        logging.getLogger(name).setLevel(logging.WARNING)

    targets = [r for r in _read_rows(selection) if int(r["added"][:4]) >= from_year]
    existing = _read_rows(out)
    if retry_errors:
        kept = [r for r in existing if not r["status"].startswith("error")]
        if len(kept) != len(existing):
            _write_all(out, kept)
        existing = kept
    done = {r["sha256"] for r in existing}
    used_today = sum(1 for r in existing if r["fetched_at"][:10] == _today())
    todo = [r for r in targets if r["sha256"] not in done][:limit]
    log.info("%d selected APKs from %d on, %d already refreshed, %d to do; %d of %d requests used today",
             len(targets), from_year, len(done & {r["sha256"] for r in targets}), len(todo),
             used_today, DAILY_LIMIT)
    limiter = limiter or RateLimiter(MIN_INTERVAL_SECONDS, DAILY_LIMIT, used_today)

    own_client = client is None
    if own_client:
        import httpx
        client = httpx.Client(timeout=httpx.Timeout(30.0))
    counts = {"ok": 0, "not_found": 0, "error": 0, "stopped_at_daily_limit": False}
    out.parent.mkdir(parents=True, exist_ok=True)
    new_file = not out.exists()
    try:
        with out.open("a", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore", lineterminator="\n")
            if new_file:
                w.writeheader()
            for n, row in enumerate(todo, 1):
                try:
                    result = lookup(client, key, row["sha256"], limiter)
                except DailyLimitReached:
                    counts["stopped_at_daily_limit"] = True
                    log.info("Daily limit of %d requests reached. Run the same command tomorrow (UTC).",
                             DAILY_LIMIT)
                    break
                record = {"sha256": row["sha256"], "androzoo_label": row["label"],
                          "androzoo_vt_detection": row["vt_detection"],
                          "androzoo_vt_scan_date": row["vt_scan_date"][:10], "added": row["added"][:10],
                          **result, "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
                if result["status"] == "ok":
                    record["refreshed_label"] = label_for(result["vt_malicious"], benign_max, malicious_min)
                w.writerow(record)
                fh.flush()
                os.fsync(fh.fileno())
                counts["ok" if result["status"] == "ok" else
                       "not_found" if result["status"] == "not_found" else "error"] += 1
                if n % 20 == 0:
                    log.info("%d/%d looked up", n, len(todo))
    finally:
        if own_client:
            client.close()
    return {**counts, "remaining": len(todo) - counts["ok"] - counts["not_found"] - counts["error"]}


def _write_all(path: Path, rows: list[dict]) -> None:
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    tmp.replace(path)


def summarize(out: Path) -> dict:
    """How many labels changed between AndroZoo's scan and today."""
    rows = [r for r in _read_rows(out) if r["status"] == "ok"]
    changes: dict[str, int] = {}
    for r in rows:
        k = f"{r['androzoo_label']}->{r['refreshed_label']}"
        changes[k] = changes.get(k, 0) + 1
    return {"refreshed": len(rows), "label_changes": changes}


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    data = ROOT / "ml" / "data" / "androzoo"
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--selection", default=str(data / "selection.csv"))
    ap.add_argument("--out", default=str(data / "vt_refreshed.csv"))
    ap.add_argument("--from-year", type=int, default=2024, help="refresh APKs added in this year or later")
    ap.add_argument("--limit", type=int, default=None, help="at most this many lookups in this run")
    ap.add_argument("--retry-errors", action="store_true")
    ap.add_argument("--summary", action="store_true", help="only print how many labels changed")
    ap.add_argument("--benign-max-detections", type=int, default=0)
    ap.add_argument("--malicious-min-detections", type=int, default=4)
    args = ap.parse_args(argv)
    if args.summary:
        print(json.dumps(summarize(Path(args.out)), indent=2, sort_keys=True))
        return 0
    result = refresh(Path(args.selection), Path(args.out), from_year=args.from_year, limit=args.limit,
                     retry_errors=args.retry_errors, benign_max=args.benign_max_detections,
                     malicious_min=args.malicious_min_detections)
    print(json.dumps({**result, **summarize(Path(args.out))}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
