"""WhatsApp bot against the real backend (in-process) and a mocked OpenWA.

The "APK" is the small zip fixture built from the suspicious test DEX
(tests/test_category.py), never a real sample.
"""
from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from clients.whatsapp_bot import main as wa
from tests.test_category import _apk

SESSION, CHAT, MSG = "s1", "000000000000@c.us", "m1"


class FakeOpenWA:
    """Mocked OpenWA HTTP API: records sent texts, serves one media file."""

    def __init__(self, media: dict[str, bytes]):
        self.media, self.texts = media, []

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["X-API-Key"] == "test-key"
        if request.url.path.endswith("/messages/send-text"):
            body = json.loads(request.content)
            self.texts.append(body["text"])
            assert body["chatId"] == CHAT
            return httpx.Response(200, json={"ok": True})
        msg_id = request.url.path.split("/")[-2]
        if msg_id in self.media:
            return httpx.Response(200, content=self.media[msg_id])
        return httpx.Response(404)


def _payload(filename="invoice.apk", size=None, msg_id=MSG, mtype="document"):
    media = {"filename": filename, "mimetype": wa.APK_MIME}
    if size is not None:
        media["sizeBytes"] = size
    return {"event": "message.received", "sessionId": SESSION,
            "data": {"chatId": CHAT, "id": msg_id, "type": mtype, "body": filename, "media": media}}


@pytest.fixture
def setup(tmp_path):
    key = tmp_path / ".api-key"
    key.write_text("test-key\n")
    settings = wa.Settings(openwa_api_key_file=key, sandbox_poll_seconds=0, sandbox_timeout_seconds=5)
    fake = FakeOpenWA({MSG: _apk(tmp_path, "suspicious").read_bytes()})
    openwa = wa.OpenWA(settings, httpx.Client(base_url="http://openwa",
                                               transport=httpx.MockTransport(fake.handler)))
    return settings, fake, openwa


def _run(bot, payload):
    response, job = bot.handle(payload)
    if job is not None:
        job[0](*job[1:])
    return response


def test_apk_goes_through_the_full_pipeline(setup, monkeypatch):
    from backend.api.main import app as backend
    from backend.hashing.lookup import HashLookupService
    from backend.hashing.verdict_store import VerdictStore
    from backend.orchestration import pipeline
    # A fresh verdict store: another test may already have remembered this fixture.
    monkeypatch.setattr(pipeline, "_lookup", HashLookupService(store=VerdictStore(":memory:")))
    # No emulator in tests: the sandbox queue only hands back a job id.
    async def fake_enqueue(*a, **kw):
        return "job-demo"
    monkeypatch.setattr(pipeline, "_enqueue_sandbox", fake_enqueue)
    settings, fake, openwa = setup
    settings = wa.Settings(openwa_api_key_file=settings.openwa_api_key_file,
                           sandbox_poll_seconds=0, sandbox_timeout_seconds=0.2)
    bot = wa.Bot(settings, openwa, wa.ApkookiesAPI(settings, TestClient(backend)))
    assert _run(bot, _payload())["status"] == "accepted"
    ack, result, follow_up = fake.texts
    assert "APK received" in ack and "invoice.apk" in ack
    # Accessibility + overlay + SMS in the app's own code is stage-3 evidence: warn and
    # send it to the sandbox; only stage 4-5 behaviour evidence would block.
    assert "Verdict: ⚠️ SUSPICIOUS" in result and "Risk score: 0.44" in result
    assert "*Why:*" in result and "Rule R002_A11Y_OVERLAY" in result     # from risk.breakdown
    assert "*MITRE ATT&CK techniques:*" in result and "T1" in result
    assert "Be careful" in result and "Report ID:" in result
    assert "Scoring mode: ML model (experimental)" in result
    assert "sandbox" in result and "message you again" in result
    assert "taking longer than expected" in follow_up                    # job never finished here
    # The same file again is answered from the verdict store, and says so.
    _run(bot, _payload())
    assert "remembered" in fake.texts[-1]


def test_too_large_is_refused_before_download(setup):
    settings, fake, openwa = setup
    bot = wa.Bot(settings, openwa, api=None)
    assert _run(bot, _payload(size=60 * 1024 * 1024))["status"] == "rejected"
    assert len(fake.texts) == 1 and "50 MiB" in fake.texts[0]


def test_missing_media_gets_a_plain_failure_message(setup):
    settings, fake, openwa = setup
    bot = wa.Bot(settings, openwa, api=None)
    _run(bot, _payload(msg_id="gone"))
    assert "analysis failed" in fake.texts[-1] and "didn't deliver" in fake.texts[-1]


class FakeAPI:
    """Backend that queues a sandbox job, which finishes on the second poll."""

    def __init__(self, final_status="done"):
        self.polls, self.final_status = 0, final_status

    def submit_apk(self, filename, data):
        return {"action": "warn", "sandbox_job_id": "job1", "report": {
            "report_id": "r1", "verdict": {"label": "suspicious"},
            "risk": {"score": 0.44, "severity": "medium", "breakdown": [
                {"step": "model", "kind": "base", "delta": 0.2, "score_after": 0.2, "detail": "xgboost"},
                {"step": "rule:R002B_A11Y_OVERLAY_ALONE", "kind": "floor", "delta": 0.24,
                 "score_after": 0.44, "detail": ""}],
                "rules_triggered": [{"rule_id": "R002B_A11Y_OVERLAY_ALONE", "description": "warn"}]}}}

    def job(self, job_id):
        self.polls += 1
        return {"status": "running" if self.polls < 2 else self.final_status, "report_id": "r1"}

    def report(self, report_id):
        return {"report_id": "r1", "verdict": {"label": "malicious"},
                "risk": {"score": 0.93, "severity": "critical", "breakdown": []},
                "mitre_attack": [{"technique_id": "T1417.002", "technique_name": "GUI Input Capture",
                                  "evidence_strength": "runtime"}]}


def test_sandbox_job_is_announced_and_followed_up(setup):
    settings, fake, openwa = setup
    api = FakeAPI()
    bot = wa.Bot(settings, openwa, api, sleep=lambda s: None)
    _run(bot, _payload())
    ack, first, update = fake.texts
    assert "sandbox" in first and "message you again" in first and "Rule R002B_A11Y_OVERLAY_ALONE" in first
    assert "Sandbox analysis finished" in update and "MALICIOUS" in update
    assert "first result: 0.44" in update and "T1417.002 GUI Input Capture (runtime)" in update
    assert api.polls == 2


def test_failed_sandbox_keeps_the_first_result(setup):
    settings, fake, openwa = setup
    bot = wa.Bot(settings, openwa, FakeAPI(final_status="failed"), sleep=lambda s: None)
    _run(bot, _payload())
    assert "first result above still stands" in fake.texts[-1]


def test_webhook_endpoint_greets_ignores_and_logs_nothing_by_default(setup, monkeypatch, tmp_path):
    settings, fake, openwa = setup
    monkeypatch.setattr(wa, "_bot", wa.Bot(settings, openwa, api=None))
    monkeypatch.chdir(tmp_path)
    client = TestClient(wa.app)
    hi = _payload(mtype="text")
    hi["data"]["body"] = "hi"
    assert client.post("/webhook", json=hi).json() == {"status": "replied"}
    assert "Send me an Android app" in fake.texts[-1]
    assert client.post("/webhook", json={"event": "session.status"}).json()["status"] == "ignored"
    assert not (tmp_path / "webhook_logs").exists()          # phone numbers not stored


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("APKOOKIES_API_URL", "http://pc:8000/")
    monkeypatch.setenv("BOT_LOG_WEBHOOKS", "true")
    s = wa.Settings.from_env()
    assert s.api_url == "http://pc:8000" and s.log_webhooks
