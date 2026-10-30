"""AndroZoo dataset builder, on a synthetic list and fake downloads (no network, no real APKs).

The "APKs" served by the fake client are the small zip fixtures built from the
benign/suspicious test DEX files (tests/test_category.py), never real samples.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import json
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

import pytest

from ml.data import build_androzoo_dataset as az
from tests.test_category import _apk

KEY = "SECRET-KEY-must-never-appear"
HEADER = ["sha256", "sha1", "md5", "dex_date", "apk_size", "pkg_name", "vercode",
          "vt_detection", "vt_scan_date", "dex_size", "added", "markets"]


def _row(i: int, *, vt="0", year=2020, size=1_000_000, markets="play.google.com", pkg=None,
         scan="06-01") -> list:
    sha = hashlib.sha256(f"row{i}".encode()).hexdigest().upper()
    scan_date = f"{year + 1}-{scan[3:]}" if scan.startswith("+1") else f"{year}-{scan}"
    return [sha, "", "", "1980-01-01 00:00:00", size, f'"{pkg or f"com.app{i}"}"', 1, vt,
            f"{scan_date} 00:00:00", 10, f"{year}-03-01 12:00:00.000000", markets]


def _write_list(path: Path, rows: list[list]) -> Path:
    with gzip.open(path, "wt", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(HEADER)
        w.writerows(rows)
    return path


@pytest.fixture
def listing(tmp_path) -> Path:
    rows = []
    i = 0
    for year, n_ben, n_mal in ((2019, 30, 5), (2020, 30, 30), (2021, 5, 30)):
        for store in ("play.google.com", "anzhi"):
            for _ in range(n_ben):
                rows.append(_row(i, year=year, markets=store)); i += 1
            for _ in range(n_mal):
                rows.append(_row(i, vt="12", year=year, markets=store)); i += 1
    rows += [
        _row(900, vt="2"),                                  # grey zone
        _row(901, vt=""),                                   # never scanned
        _row(902, size=40 * 1024 * 1024),                   # over the size cap
        _row(903, vt="12", markets="VirusShare"),           # no store to match
        _row(904, year=2015),                               # outside the date range
        _row(905, pkg="com.app0"), _row(906, pkg="com.app0"),   # more versions of a package
    ]
    return _write_list(tmp_path / "list.csv.gz", rows)


CFG = az.SampleConfig(per_class=20, since="2018-01-01", until="2025-12-31")


def test_sampling_labels_exclusions_and_balance(listing):
    chosen, summary = az.sample(listing, CFG)
    assert summary["excluded"] == {"grey_zone_detections": 1, "no_virustotal_result": 1,
                                   "larger_than_size_cap": 1, "no_store_to_match": 1,
                                   "outside_date_range": 1}
    counts = Counter(r["label"] for r in chosen)
    assert counts["benign"] == counts["malicious"] == 20
    # Equal numbers of each class in every year and store: neither time nor the
    # store can stand in for the label.
    cells = Counter((r["added"][:4], r["store"], r["label"]) for r in chosen)
    for year in ("2019", "2020", "2021"):
        for store in ("play", "anzhi"):
            assert cells[(year, store, "benign")] == cells[(year, store, "malicious")]
    assert {r["store"] for r in chosen} == {"play", "anzhi"}
    assert len({r["pkg_hash"] for r in chosen}) == len(chosen)        # one APK per package
    assert all(r["sha256"] == r["sha256"].lower() for r in chosen)
    assert all("com.app" not in json.dumps(r) for r in chosen)          # package names not kept


def test_sampling_is_deterministic_per_seed(listing):
    a, _ = az.sample(listing, CFG)
    b, _ = az.sample(listing, CFG)
    c, _ = az.sample(listing, az.SampleConfig(**{**CFG.__dict__, "seed": 1}))
    assert [r["sha256"] for r in a] == [r["sha256"] for r in b]
    assert [r["sha256"] for r in a] != [r["sha256"] for r in c]


def test_shortfall_is_reported(listing):
    _, summary = az.sample(listing, az.SampleConfig(**{**CFG.__dict__, "per_class": 500}))
    assert summary["shortfall_per_class"]["benign"] > 0


def test_water_fill_spreads_over_years_and_keeps_scarce_ones():
    assert az._water_fill({"2019": 100, "2020": 100, "2025": 3}, 60) == {"2019": 29, "2020": 28, "2025": 3}
    assert sum(az._water_fill({"a": 5, "b": 5}, 60).values()) == 10       # shortfall, not overflow


def test_scarce_recent_year_gets_all_it_has(tmp_path):
    rows, i = [], 0
    for year, n_ben, n_mal in ((2019, 40, 40), (2020, 40, 40), (2024, 40, 2)):
        for _ in range(n_ben):
            rows.append(_row(i, year=year)); i += 1
        for _ in range(n_mal):
            rows.append(_row(i, vt="12", year=year)); i += 1
    chosen, summary = az.sample(_write_list(tmp_path / "l.csv.gz", rows), CFG)
    assert summary["per_year"]["2024"]["taken_per_class"] == 2
    assert Counter(r["label"] for r in chosen) == {"benign": 20, "malicious": 20}


def test_store_of():
    assert az.store_of(["play.google.com", "anzhi"]) == "play"
    assert az.store_of(["PlayDrone"]) == "play"
    assert az.store_of(["VirusShare", "appchina", "anzhi"]) == "anzhi"
    assert az.store_of(["VirusShare"]) == az.store_of(["unknown"]) == "none"


def test_benign_follows_the_malicious_store_mix(tmp_path):
    # Malicious: 30 from appchina, 10 from Play. Benign is plentiful in both, so the
    # sample must mirror the malicious mix (3:1), not the benign one.
    rows, i = [], 0
    for store, n_ben, n_mal in (("appchina", 100, 30), ("play.google.com", 300, 10)):
        for _ in range(n_ben):
            rows.append(_row(i, markets=store)); i += 1
        for _ in range(n_mal):
            rows.append(_row(i, vt="9", markets=store)); i += 1
    chosen, summary = az.sample(_write_list(tmp_path / "l.csv.gz", rows), CFG)
    mix = Counter((r["store"], r["label"]) for r in chosen)
    assert mix == {("appchina", "benign"): 15, ("appchina", "malicious"): 15,
                   ("play", "benign"): 5, ("play", "malicious"): 5}
    assert summary["stores"]["appchina"]["selected_per_class"] == 15
    assert summary["play_only_malicious"] == 5


def test_settled_labels_are_preferred_and_reported(tmp_path):
    # Half the APKs were scanned a year after being added (mature), half 3 months after.
    rows, i = [], 0
    for scan in ("+1-06-01", "06-01"):
        for vt in ("0", "9"):
            for _ in range(30):
                rows.append(_row(i, vt=vt, year=2024, scan=scan)); i += 1
    cfg = az.SampleConfig(**{**CFG.__dict__, "min_scan_gap_days": 180})
    chosen, summary = az.sample(_write_list(tmp_path / "l.csv.gz", rows), cfg)
    assert len(chosen) == 40 and all(r["mature"] == 1 for r in chosen)
    m = summary["label_maturity"]
    assert m["recent_2024_on"]["malicious"] == {"selected": 20, "mature": 20}
    # With a stricter gap nothing qualifies: still sampled, but reported as not mature.
    cfg = az.SampleConfig(**{**CFG.__dict__, "min_scan_gap_days": 800})
    chosen, summary = az.sample(_write_list(tmp_path / "l.csv.gz", rows), cfg)
    assert len(chosen) == 40 and summary["label_maturity"]["mature_per_class"] == {"benign": 0, "malicious": 0}


def test_proportional_fill():
    assert az._proportional_fill({"a": 3, "b": 1}, {"a": 100, "b": 100}, 20) == {"a": 15, "b": 5}
    assert az._proportional_fill({"a": 3, "b": 1}, {"a": 4, "b": 100}, 20) == {"a": 4, "b": 16}
    assert az._proportional_fill({"a": 1, "b": 1, "c": 1}, {"a": 9, "b": 9, "c": 9}, 10) in (
        {"a": 4, "b": 3, "c": 3}, {"a": 3, "b": 4, "c": 3}, {"a": 3, "b": 3, "c": 4})
    assert sum(az._proportional_fill({"a": 1}, {"a": 2}, 10).values()) == 2


def test_bottom_k_keeps_one_representative_per_package():
    pool = az._BottomK(2)
    pool.offer(5, "p", 9, {"v": "late"})
    pool.offer(5, "p", 1, {"v": "best"})
    pool.offer(1, "q", 3, {}); pool.offer(9, "r", 1, {})     # r is outside the 2 smallest
    assert set(pool.items) == {"p", "q"} and pool.items["p"][1] == {"v": "best"}


def test_select_needs_no_key_and_writes_the_committed_selection(listing, tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ANDROZOO_API_KEY", raising=False)
    out, work = tmp_path / "out", tmp_path / "work"
    args = ["--list", str(listing), "--work-dir", str(work), "--out", str(out),
            "--per-class", "20", "--until", "2025-12-31", "--dry-run"]
    assert az.main(args) == 0
    assert sorted(p.name for p in out.iterdir()) == ["selection.csv", "selection.json"]
    assert not work.exists() and "nothing downloaded" in capsys.readouterr().out
    meta = json.loads((out / "selection.json").read_text())
    assert meta["list_sha256"] == hashlib.sha256(listing.read_bytes()).hexdigest()
    assert "com.app" not in (out / "selection.csv").read_text()      # package names not kept
    assert b"\r" not in (out / "selection.csv").read_bytes()         # same bytes on every OS
    with pytest.raises(SystemExit, match="replace-selection"):
        az.main(args)                                                 # never silently replaced
    assert az.main(args + ["--replace-selection", "--seed", "7"]) == 0

    # A run reads the committed selection; it never takes the list.
    with pytest.raises(SystemExit, match="only used with --select"):
        az.main(["--list", str(listing), "--out", str(out), "--work-dir", str(work)])
    run = az.Run(work=work, out=out)
    rows, summary = az.load_selection(run)
    assert len(rows) == 40 and summary["config"]["seed"] == 7
    # Progress belongs to one selection: a changed selection.csv needs a new work dir.
    az._write_csv(run.selection_csv, rows[:10], az.SAMPLE_COLUMNS)
    with pytest.raises(SystemExit, match="different selection"):
        az.load_selection(run)


# --- downloads -------------------------------------------------------------------
class FakeResponse:
    def __init__(self, status: int, body: bytes = b"") -> None:
        self.status_code, self._body = status, body

    def iter_bytes(self, n):
        yield from (self._body[i:i + n] for i in range(0, len(self._body), n))


class FakeClient:
    """Serves bytes by sha256; raises like httpx would, with the key in the message."""

    def __init__(self, files: dict[str, bytes], explode: bool = False, **_kw) -> None:
        self.files, self.explode, self.calls = files, explode, []

    @contextmanager
    def stream(self, method, url, params):
        self.calls.append(params["sha256"])
        if self.explode:
            raise ConnectionError(f"failed GET {url}?apikey={params['apikey']}")
        body = self.files.get(params["sha256"])
        yield FakeResponse(200 if body is not None else 404, body or b"")

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_download_errors_never_contain_the_key(tmp_path, monkeypatch):
    monkeypatch.setattr(az.time, "sleep", lambda s: None)
    err = az.download(FakeClient({}, explode=True), KEY, "a" * 64, tmp_path / "x.apk")
    assert err == "ConnectionError" and KEY not in err
    assert az.download(FakeClient({}), KEY, "a" * 64, tmp_path / "x.apk") == "http_404"
    # Content that doesn't hash to the requested sha256 is rejected and not kept.
    assert az.download(FakeClient({"a" * 64: b"tampered"}), KEY, "a" * 64,
                       tmp_path / "x.apk") == "sha256_mismatch"
    assert list(tmp_path.iterdir()) == []


def test_key_only_from_environment_and_concurrency_capped(tmp_path, monkeypatch):
    run = az.Run(work=tmp_path, out=tmp_path / "out")
    monkeypatch.delenv("ANDROZOO_API_KEY", raising=False)
    with pytest.raises(SystemExit, match="ANDROZOO_API_KEY is not set"):
        az.download_and_extract(run, [], concurrency=5, extract_workers=1,
                                temp_budget_gb=1, timeout=60, retry_failed=False)
    monkeypatch.setenv("ANDROZOO_API_KEY", KEY)
    with pytest.raises(SystemExit, match="1..20"):
        az.download_and_extract(run, [], concurrency=21, extract_workers=1,
                                temp_budget_gb=1, timeout=60, retry_failed=False)
    assert "apikey" not in " ".join(az.parse_args([]).__dict__)


def test_extract_and_delete_always_deletes(tmp_path):
    apk = _apk(tmp_path, "suspicious")
    good = tmp_path / ("a" * 64 + ".apk")
    apk.rename(good)
    sha, feats, err, _ = az._extract_and_delete(str(good), 120)
    assert err is None and not good.exists()
    assert feats["api_rules"] and len(feats["scalars"]) == 19
    assert feats["shipped_model"]["fingerprint"] and "permissions" in feats
    bad = tmp_path / ("b" * 64 + ".apk")
    bad.write_bytes(b"not an apk")
    _, feats, err, _ = az._extract_and_delete(str(bad), 120)
    assert not bad.exists()


def test_byte_budget():
    b = az.ByteBudget(100)
    b.acquire(60); b.acquire(40)
    assert b.used == 100
    b.release(60)
    assert b.used == 40


def test_full_run_resumes_and_writes_the_outputs(tmp_path, monkeypatch):
    """End to end with fake downloads: features extracted by the real static analysis in
    worker processes, APKs deleted, outputs written, and a re-run does nothing."""
    files = {}
    rows = []
    for i, name in enumerate(("suspicious", "benign")):
        data = _apk(tmp_path, name).read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        files[sha] = data
        rows.append({"sha256": sha, "label": ["malicious", "benign"][i], "vt_detection": "9",
                     "vt_scan_date": "2021-01-01", "added": "2021-01-01 00:00:00",
                     "dex_date": "", "apk_size": str(len(data)), "markets": "x", "pkg_hash": str(i)})
    rows.append({**rows[0], "sha256": "c" * 64, "pkg_hash": "2"})        # not on the server
    client = FakeClient(files)
    monkeypatch.setattr("httpx.Client", lambda **kw: client)
    monkeypatch.setenv("ANDROZOO_API_KEY", KEY)
    run = az.Run(work=tmp_path / "work", out=tmp_path / "out")
    kw = dict(concurrency=2, extract_workers=1, temp_budget_gb=0.01, timeout=120, retry_failed=False)
    az.download_and_extract(run, rows, **kw)
    assert not run.apk_dir.exists()                                    # nothing left on disk

    run.out.mkdir()
    az._write_csv(run.out / "selection.csv", rows, az.SAMPLE_COLUMNS)
    (run.out / "selection.json").write_text("{}")
    summary = {"config": az.asdict(CFG), "selected": {"malicious": 2, "benign": 1},
               "shortfall_per_class": {}, "per_year": {}, "excluded": {}, "rows_read": 3,
               "added_range": ["2021-01-01", "2021-01-01"], "vt_scan_range": [None, None],
               "list_file": "list.csv.gz"}
    args = az.parse_args([])
    desc = az.finalize(run, rows, summary, args)
    assert desc["extracted_ok"] == {"malicious": 1, "benign": 1}
    assert desc["failures_by_stage_and_error"] == {"download:http_404": 1}
    assert sorted(p.name for p in run.out.iterdir()) == ["DATASET.md", "features.jsonl.gz", "samples.csv",
                                                         "selection.csv", "selection.json"]
    with gzip.open(run.out / "features.jsonl.gz", "rt") as fh:
        recs = [json.loads(line) for line in fh]
    assert {r["label"] for r in recs} == {"malicious", "benign"}
    for p in [*run.out.iterdir(), run.failures]:
        text = p.read_bytes()
        assert KEY.encode() not in text and str(tmp_path).encode() not in text

    calls = len(client.calls)
    az.download_and_extract(run, rows, **kw)                           # resume: nothing to do
    assert len(client.calls) == calls

    # The pre-commit check passes, and catches stray files and the key.
    assert az.main(["--check", "--out", str(run.out)]) == 0
    (run.out / "notes.txt").write_text("x")
    assert any("unexpected files" in p for p in az.check_outputs(run.out))
    (run.out / "notes.txt").unlink()
    with open(run.out / "DATASET.md", "a") as fh:
        fh.write(KEY)
    assert any("API key" in p for p in az.check_outputs(run.out))
