"""APKookies WhatsApp bot: OpenWA webhook -> full APKookies pipeline -> plain-language reply.

Flow for an APK sent as a WhatsApp document:
  1. reject it straight away if WhatsApp says it's over 50 MiB;
  2. acknowledge immediately ("APK received, analysing");
  3. in the background: download it from OpenWA (in memory, never written to
     disk), submit it to the backend's POST /v1/submit/apk, which runs the whole
     pipeline (hash lookup, static analysis, knowledge graph, rules, scoring,
     MITRE mapping, and the sandbox when the score is uncertain);
  4. reply with the verdict, score, advice, the top reasons from
     risk.breakdown and the MITRE ATT&CK techniques;
  5. if a sandbox job was queued, say so, poll GET /v1/jobs/{id}, and send an
     update when it finishes.

Run it on an isolated machine: anyone who knows the number can
send it a real (malicious) APK, and the sandbox runs there. Settings come from
the environment (`uvicorn clients.whatsapp_bot.main:app --port 9000 --env-file .env`);
see the bot section of .env.example.
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

import httpx
from fastapi import BackgroundTasks, FastAPI, Request

log = logging.getLogger("apkookies.whatsapp_bot")

MAX_APK_BYTES = 50 * 1024 * 1024        # 50 MiB, also enforced after download
APK_MIME = "application/vnd.android.package-archive"


# ============================================================
# SETTINGS
# ============================================================

def _env_bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    openwa_url: str = "http://localhost:2785"
    openwa_api_key_file: Path = Path("openwa/.api-key")
    api_url: str = "http://localhost:8000"          # APKookies backend (backend/api/main.py)
    # Raw webhook payloads contain senders' phone numbers: off unless asked for.
    log_webhooks: bool = False
    log_dir: Path = Path("webhook_logs")
    sandbox_poll_seconds: float = 20.0
    sandbox_timeout_seconds: float = 1800.0
    analysis_timeout_seconds: float = 900.0

    @classmethod
    def from_env(cls) -> "Settings":
        d = cls()
        return cls(
            openwa_url=os.environ.get("OPENWA_URL", d.openwa_url).rstrip("/"),
            openwa_api_key_file=Path(os.environ.get("OPENWA_API_KEY_FILE", str(d.openwa_api_key_file))),
            api_url=os.environ.get("APKOOKIES_API_URL", d.api_url).rstrip("/"),
            log_webhooks=_env_bool("BOT_LOG_WEBHOOKS", d.log_webhooks),
            log_dir=Path(os.environ.get("BOT_LOG_DIR", str(d.log_dir))),
            sandbox_poll_seconds=float(os.environ.get("BOT_SANDBOX_POLL_SECONDS", d.sandbox_poll_seconds)),
            sandbox_timeout_seconds=float(os.environ.get("BOT_SANDBOX_TIMEOUT_SECONDS",
                                                         d.sandbox_timeout_seconds)),
            analysis_timeout_seconds=float(os.environ.get("BOT_ANALYSIS_TIMEOUT_SECONDS",
                                                          d.analysis_timeout_seconds)),
        )


# ============================================================
# OPENWA (WhatsApp gateway) AND APKOOKIES API CLIENTS
# ============================================================

class OpenWA:
    def __init__(self, settings: Settings, client: Optional[httpx.Client] = None) -> None:
        self.settings = settings
        self.client = client or httpx.Client(base_url=settings.openwa_url, timeout=180.0)

    def _headers(self) -> dict:
        # Read on every call: OpenWA can rotate the key file.
        return {"X-API-Key": self.settings.openwa_api_key_file.read_text(encoding="utf-8").strip()}

    def send_text(self, session_id: str, chat_id: str, text: str) -> None:
        r = self.client.post(f"/api/sessions/{session_id}/messages/send-text",
                             headers=self._headers(), json={"chatId": chat_id, "text": text})
        r.raise_for_status()

    def download_media(self, session_id: str, chat_id: str, message_id: str) -> bytes:
        r = self.client.get(f"/api/sessions/{session_id}/messages/{chat_id}/{message_id}/media",
                            headers=self._headers())
        if r.status_code == 404:
            raise MediaUnavailable()
        r.raise_for_status()
        return r.content


class MediaUnavailable(Exception):
    """OpenWA has no stored media for the message (its inbound download timed out)."""


class ApkookiesAPI:
    def __init__(self, settings: Settings, client: Optional[httpx.Client] = None) -> None:
        self.client = client or httpx.Client(base_url=settings.api_url,
                                             timeout=settings.analysis_timeout_seconds)

    def submit_apk(self, filename: str, data: bytes) -> dict:
        r = self.client.post("/v1/submit/apk", files={"file": (filename, data, APK_MIME)},
                             data={"touchpoint": "whatsapp_bot"})
        r.raise_for_status()
        return r.json()

    def job(self, job_id: str) -> dict:
        r = self.client.get(f"/v1/jobs/{job_id}")
        r.raise_for_status()
        return r.json()

    def report(self, report_id: str) -> dict:
        r = self.client.get(f"/v1/reports/{report_id}")
        r.raise_for_status()
        return r.json()


# ============================================================
# MESSAGES
# ============================================================

_VERDICT = {
    "malicious": "🚨 MALICIOUS",
    "suspicious": "⚠️ SUSPICIOUS",
    "benign": "✅ NO STRONG SIGNS OF DANGER",
}
_ADVICE = {
    "block": "Do NOT install this app, and don't enter any OTP, PIN or password in it.",
    "warn": "Be careful: avoid installing it, and never share OTPs or passwords with it.",
    "allow": "No strong signs of danger were found. Still only install apps you asked for, "
             "from the Play Store.",
}


_MODE_LABEL = {"rules": "rules (transparent, no ML)", "model": "ML model (experimental)",
               "retrained": "retrained ML model"}


def _short(text: str, limit: int = 160) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def top_reasons(risk: dict, n: int = 3) -> list[str]:
    """The score steps that raised the score most (risk.breakdown), as short lines."""
    rules = {h.get("rule_id"): h.get("description", "") for h in risk.get("rules_triggered") or []}
    steps = [s for s in risk.get("breakdown") or [] if (s.get("delta") or 0) > 0.005]
    steps.sort(key=lambda s: -s["delta"])
    lines = []
    for s in steps[:n]:
        step = s.get("step", "")
        if step.startswith("rule:"):
            rule_id = step.split(":", 1)[1]
            text = f"Rule {rule_id}: {rules.get(rule_id) or s.get('detail', '')}"
        elif step == "model":
            text = f"Model assessment: {s.get('detail', '')}"
        else:
            text = s.get("detail") or step
        lines.append(f"• +{s['delta']:.2f} {_short(text)}")
    return lines


def mitre_lines(techniques: list[dict], n: int = 5) -> list[str]:
    lines = []
    for t in techniques[:n]:
        name = t.get("technique_name") or ""
        strength = f" ({t['evidence_strength']})" if t.get("evidence_strength") else ""
        lines.append(f"• {t.get('technique_id')} {name}{strength}".rstrip())
    if len(techniques) > n:
        lines.append(f"• …and {len(techniques) - n} more")
    return lines


def _verdict_block(report: dict) -> str:
    verdict = (report.get("verdict") or {}).get("label", "unknown")
    risk = report.get("risk") or {}
    score = risk.get("score")
    score_text = f"{score:.2f} / 1.00" if isinstance(score, (int, float)) else "n/a"
    lines = [f"🛡️ Verdict: {_VERDICT.get(verdict, '❔ COULD NOT DECIDE')}",
             f"📈 Risk score: {score_text} ({str(risk.get('severity', 'unknown')).lower()})"]
    mode = risk.get("scoring_mode")
    if mode:
        lines.append(f"⚙️ Scoring mode: {_MODE_LABEL.get(mode, mode)}")
    reasons = top_reasons(risk)
    if reasons:
        lines += ["", "*Why:*", *reasons]
    mitre = mitre_lines(report.get("mitre_attack") or [])
    if mitre:
        lines += ["", "*MITRE ATT&CK techniques:*", *mitre]
    return "\n".join(lines)


def format_result(response: dict, filename: str) -> str:
    report = response.get("report") or {}
    action = response.get("action", "warn")
    parts = ["🔍 *APKookies analysis complete*", "", f"📄 File: {filename}", _verdict_block(report),
             "", f"🔧 Advice: {_ADVICE.get(action, _ADVICE['warn'])}"]
    if response.get("sandbox_job_id"):
        parts += ["", "🔬 This app is now also being run in our sandbox (deep analysis). "
                      "I'll message you again when it finishes."]
    parts += ["", "ℹ️ Generated automatically by APKookies. Report ID: " + str(report.get("report_id", "?"))]
    return "\n".join(parts)


def format_sandbox_update(report: dict, filename: str, first_score: Optional[float]) -> str:
    risk = report.get("risk") or {}
    change = ""
    if isinstance(first_score, (int, float)) and isinstance(risk.get("score"), (int, float)):
        change = f" (first result: {first_score:.2f})"
    return "\n".join(["🔬 *Sandbox analysis finished*", "", f"📄 File: {filename}",
                      _verdict_block(report) + change, "",
                      "ℹ️ This result replaces the first one. Report ID: " + str(report.get("report_id", "?"))])


ACK = ("🔎 *APK received!*\n\n📄 File: {filename}\n\n"
       "APKookies is analysing it now. This usually takes under a minute. ⏳")
TOO_LARGE = ("⚠️ *This APK is too large to analyse.*\n\n📄 File: {filename}\n"
             "The limit is 50 MiB.")
FAILED = ("❌ *APK analysis failed.*\n\n📄 File: {filename}\n\n"
          "I received your APK but couldn't analyse it ({reason}). Please try sending it again.")
SANDBOX_FAILED = ("🔬 The sandbox couldn't finish analysing {filename}. "
                  "The first result above still stands.")
SANDBOX_TIMEOUT = ("🔬 The sandbox is taking longer than expected for {filename}. "
                   "The first result above still stands; an analyst can check report {report_id}.")
GREETING = ("👋 *Hi! This is the APKookies WhatsApp bot.*\n\n"
            "🛡️ Send me an Android app (.apk file) and I'll check it for signs of banking fraud.")


# ============================================================
# BOT
# ============================================================

def _mask(chat_id: Optional[str]) -> str:
    # Chat IDs are phone numbers: keep them out of the console log.
    return f"…{str(chat_id)[-4:]}" if chat_id else "?"


def is_apk_document(data: dict) -> bool:
    if data.get("type") != "document":
        return False
    media = data.get("media") or {}
    filename = str(media.get("filename") or data.get("body") or "").lower()
    return filename.endswith(".apk") or str(media.get("mimetype") or "").lower() == APK_MIME


@dataclass
class Bot:
    settings: Settings
    openwa: OpenWA
    api: ApkookiesAPI
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic

    def say(self, session_id: str, chat_id: str, text: str) -> None:
        try:
            self.openwa.send_text(session_id, chat_id, text)
        except Exception as e:  # noqa: BLE001 - a failed reply must not crash the worker
            log.warning("could not send a message to %s: %s", _mask(chat_id), type(e).__name__)

    def handle(self, payload: dict) -> tuple[dict, Optional[tuple]]:
        """Decide what to do with one webhook. Returns (HTTP response, background job or None)."""
        if payload.get("event") != "message.received":
            return {"status": "ignored", "reason": "not a received message"}, None
        data = payload.get("data") or {}
        session_id = payload.get("sessionId") or data.get("sessionId")
        chat_id, message_id = data.get("chatId"), data.get("id")
        if not (session_id and chat_id and message_id):
            return {"status": "ignored", "reason": "missing session/chat/message"}, None

        if data.get("type") in ("text", "chat"):
            if str(data.get("body", "")).strip().lower() in ("hi", "hello", "hey", "hii", "help", "start"):
                self.say(session_id, chat_id, GREETING)
                return {"status": "replied"}, None
            return {"status": "ignored", "reason": "text message"}, None
        if not is_apk_document(data):
            return {"status": "ignored", "reason": "not an APK"}, None

        media = data.get("media") or {}
        filename = str(media.get("filename") or data.get("body") or "received.apk")
        try:
            size = int(media.get("sizeBytes")) if media.get("sizeBytes") is not None else None
        except (TypeError, ValueError):
            size = None
        if size is not None and size > MAX_APK_BYTES:
            self.say(session_id, chat_id, TOO_LARGE.format(filename=filename))
            return {"status": "rejected", "reason": "too large"}, None

        self.say(session_id, chat_id, ACK.format(filename=filename))
        return ({"status": "accepted", "filename": filename},
                (self.process_apk, session_id, chat_id, message_id, filename))

    def process_apk(self, session_id: str, chat_id: str, message_id: str, filename: str) -> None:
        log.info("analysing %s from %s", filename, _mask(chat_id))
        try:
            data = self.openwa.download_media(session_id, chat_id, message_id)
            if not data:
                raise ValueError("empty file")
            if len(data) > MAX_APK_BYTES:
                self.say(session_id, chat_id, TOO_LARGE.format(filename=filename))
                return
            response = self.api.submit_apk(filename, data)
            del data                                   # the APK is never written to disk here
        except Exception as e:  # noqa: BLE001
            reason = {"MediaUnavailable": "WhatsApp didn't deliver the file to the bot",
                      "ValueError": "the file was empty"}.get(type(e).__name__, "a server error")
            log.warning("analysis of %s failed: %s", filename, type(e).__name__)
            self.say(session_id, chat_id, FAILED.format(filename=filename, reason=reason))
            return
        self.say(session_id, chat_id, format_result(response, filename))
        job_id = response.get("sandbox_job_id")
        if job_id:
            first = (response.get("report") or {}).get("risk", {}).get("score")
            self.follow_sandbox(session_id, chat_id, filename, job_id,
                                (response.get("report") or {}).get("report_id"), first)

    def follow_sandbox(self, session_id: str, chat_id: str, filename: str, job_id: str,
                       report_id: Optional[str], first_score: Optional[float]) -> None:
        deadline = self.clock() + self.settings.sandbox_timeout_seconds
        while self.clock() < deadline:
            self.sleep(self.settings.sandbox_poll_seconds)
            try:
                job = self.api.job(job_id)
            except Exception as e:  # noqa: BLE001 - transient API errors: keep polling
                log.warning("sandbox job poll failed: %s", type(e).__name__)
                continue
            status = job.get("status")
            if status == "done":
                try:
                    report = self.api.report(job.get("report_id") or report_id)
                except Exception as e:  # noqa: BLE001
                    log.warning("could not fetch the sandbox report: %s", type(e).__name__)
                    self.say(session_id, chat_id, SANDBOX_FAILED.format(filename=filename))
                    return
                self.say(session_id, chat_id, format_sandbox_update(report, filename, first_score))
                return
            if status == "failed":
                self.say(session_id, chat_id, SANDBOX_FAILED.format(filename=filename))
                return
        self.say(session_id, chat_id, SANDBOX_TIMEOUT.format(filename=filename, report_id=report_id))


# ============================================================
# WEB APP
# ============================================================

app = FastAPI(title="APKookies WhatsApp Bot")
_bot: Optional[Bot] = None


def bot() -> Bot:
    global _bot
    if _bot is None:
        settings = Settings.from_env()
        _bot = Bot(settings, OpenWA(settings), ApkookiesAPI(settings))
    return _bot


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "service": "APKookies WhatsApp Bot"}


@app.post("/webhook")
async def webhook(request: Request, background_tasks: BackgroundTasks) -> dict:
    payload = await request.json()
    b = bot()
    if b.settings.log_webhooks:
        b.settings.log_dir.mkdir(parents=True, exist_ok=True)
        name = f"webhook_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json"
        (b.settings.log_dir / name).write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                                              encoding="utf-8")
    response, job = b.handle(payload)
    if job is not None:
        background_tasks.add_task(*job)
    return response
