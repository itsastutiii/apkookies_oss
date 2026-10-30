"""Optional VirusTotal label refresh, against a fake client (no network, no key)."""
from __future__ import annotations

import csv
import hashlib

import pytest

from ml.data import build_androzoo_dataset as az
from ml.data import refresh_vt_labels as vt

KEY = "VT-SECRET-must-never-appear"


def _sha(i: int) -> str:
    return hashlib.sha256(f"apk{i}".encode()).hexdigest()


@pytest.fixture
def selection(tmp_path):
    rows = []
    for i, (year, label, det) in enumerate([(2022, "benign", 0), (2024, "benign", 0),
                                            (2025, "malicious", 5), (2026, "benign", 0),
                                            (2026, "malicious", 4)]):
        rows.append({"sha256": _sha(i), "label": label, "vt_detection": det,
                     "vt_scan_date": f"{year}-05-01 00:00:00", "added": f"{year}-03-01 00:00:00"})
    path = tmp_path / "selection.csv"
    az._write_csv(path, rows, az.SAMPLE_COLUMNS)
    return path


class FakeResponse:
    def __init__(self, status, body=None):
        self.status_code, self._body = status, body or {}

    def json(self):
        return self._body


class FakeVT:
    """Current reports by sha256. Records every call; refuses anything but a GET by hash."""

    def __init__(self, reports, statuses=None):
        self.reports, self.statuses, self.calls = reports, statuses or {}, []

    def get(self, url, headers):
        assert url.startswith("https://www.virustotal.com/api/v3/files/") and headers == {"x-apikey": KEY}
        sha = url.rsplit("/", 1)[1]
        self.calls.append(sha)
        if sha in self.statuses:
            status = self.statuses[sha]
            if isinstance(status, Exception):
                raise status
            return FakeResponse(status)
        if sha not in self.reports:
            return FakeResponse(404)
        return FakeResponse(200, {"data": {"attributes": {
            "last_analysis_stats": {"malicious": self.reports[sha], "undetected": 60},
            "last_analysis_date": 1790000000}}})


class FakeClock:
    def __init__(self):
        self.now, self.sleeps = 0.0, []

    def clock(self):
        return self.now

    def sleep(self, s):
        self.sleeps.append(s)
        self.now += s


def _run(selection, out, client, *, used_today=0, **kw):
    fc = FakeClock()
    limiter = vt.RateLimiter(vt.MIN_INTERVAL_SECONDS, vt.DAILY_LIMIT, used_today, fc.clock, fc.sleep)
    result = vt.refresh(selection, out, from_year=2024, limit=kw.pop("limit", None),
                        retry_errors=kw.pop("retry_errors", False), benign_max=0, malicious_min=4,
                        client=client, limiter=limiter)
    return result, fc


def test_refreshes_recent_hashes_only_and_relabels(selection, tmp_path, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", KEY)
    out = tmp_path / "vt_refreshed.csv"
    client = FakeVT({_sha(1): 7, _sha(2): 12, _sha(3): 2})      # sha(4) unknown to VT
    result, fc = _run(selection, out, client)
    assert set(client.calls) == {_sha(i) for i in (1, 2, 3, 4)}      # 2022 not asked
    assert result == {"ok": 3, "not_found": 1, "error": 0, "stopped_at_daily_limit": False, "remaining": 0}
    rows = {r["sha256"]: r for r in csv.DictReader(out.open())}
    assert rows[_sha(1)]["refreshed_label"] == "malicious"           # benign then, flagged now
    assert rows[_sha(3)]["refreshed_label"] == "grey_zone"
    assert rows[_sha(4)]["status"] == "not_found"
    assert vt.summarize(out)["label_changes"] == {"benign->malicious": 1, "malicious->malicious": 1,
                                                  "benign->grey_zone": 1}
    # Free tier: requests at least 15 s apart.
    assert fc.sleeps == [vt.MIN_INTERVAL_SECONDS] * 3
    assert KEY not in out.read_text()


def test_resumes_and_stops_at_the_daily_limit(selection, tmp_path, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", KEY)
    out = tmp_path / "vt_refreshed.csv"
    client = FakeVT({_sha(1): 0, _sha(2): 9, _sha(3): 0, _sha(4): 9})
    result, _ = _run(selection, out, client, used_today=vt.DAILY_LIMIT - 2)
    assert result["stopped_at_daily_limit"] and len(client.calls) == 2 and result["remaining"] == 2
    result, _ = _run(selection, out, client)                        # "the next day"
    assert len(client.calls) == 4 and result["ok"] == 2               # only the two left
    assert len(list(csv.DictReader(out.open()))) == 4


def test_errors_never_carry_the_key_and_can_be_retried(selection, tmp_path, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", KEY)
    monkeypatch.setattr(vt.time, "sleep", lambda s: None)
    out = tmp_path / "vt_refreshed.csv"
    boom = ConnectionError(f"GET with x-apikey {KEY}")
    client = FakeVT({_sha(1): 0, _sha(2): 9, _sha(3): 0, _sha(4): 9}, statuses={_sha(2): boom})
    result, _ = _run(selection, out, client)
    assert result["error"] == 1
    text = out.read_text()
    assert "error:ConnectionError" in text and KEY not in text
    client.statuses = {}
    result, _ = _run(selection, out, client, retry_errors=True)
    assert result == {"ok": 1, "not_found": 0, "error": 0, "stopped_at_daily_limit": False, "remaining": 0}
    assert all(r["status"] == "ok" for r in csv.DictReader(out.open()))


def test_key_only_from_environment_and_rejected_key_stops(selection, tmp_path, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    with pytest.raises(SystemExit, match="VT_API_KEY is not set"):
        _run(selection, tmp_path / "o.csv", FakeVT({}))
    monkeypatch.setenv("VT_API_KEY", KEY)
    with pytest.raises(SystemExit, match="rejected the key"):
        _run(selection, tmp_path / "o.csv", FakeVT({}, statuses={_sha(1): 401}))


def test_never_uploads():
    # Lookups by hash only: no POST and no upload endpoint anywhere in the script.
    source = open(vt.__file__).read()
    assert ".post(" not in source and "/upload" not in source and "/files\"" not in source


def test_rate_limiter_daily_cap():
    fc = FakeClock()
    lim = vt.RateLimiter(15, 2, 0, fc.clock, fc.sleep)
    lim.wait(); lim.wait()
    with pytest.raises(vt.DailyLimitReached):
        lim.wait()
