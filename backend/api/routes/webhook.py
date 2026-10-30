"""/v1/webhook — WhatsApp/SMS bot intake.

Accepts forwarded URLs or APK files and returns a PLAIN-LANGUAGE verdict. URL
flow is primary (enables analysis BEFORE the victim downloads anything).

TODO: verify provider signatures (WhatsApp Cloud API / Twilio) on inbound
webhooks; handle media download for forwarded APK attachments.
"""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from backend.api.dependencies import resolve_action
from backend.orchestration import analyze
from schemas.report import InputType, Touchpoint

router = APIRouter()


class BotMessage(BaseModel):
    sender: str
    text: str | None = None          # may contain a URL
    media_url: str | None = None     # provider-hosted forwarded file (e.g. APK)


class BotReply(BaseModel):
    verdict: str
    action: str
    message: str                     # plain-language reply to send back


def _plain_language(verdict: str, action: str) -> str:
    templates = {
        "block": "⚠️ This looks dangerous. Do NOT install or enter any details. "
                 "It shows signs of fraud/banking malware.",
        "warn": "⚠️ Be careful. This could be risky — avoid installing it and do not "
                "share OTPs or passwords.",
        "allow": "✅ No strong signs of danger were found, but stay cautious with "
                 "anything you didn't request.",
    }
    return templates.get(action, templates["warn"])


@router.post("/webhook/message", response_model=BotReply)
async def inbound_message(msg: BotMessage) -> BotReply:
    url = _extract_url(msg.text)
    if url:
        result = await analyze(InputType.url, url=url, touchpoint=Touchpoint.whatsapp_bot)
    elif msg.media_url:
        # TODO: download the forwarded media, detect signature, run APK pipeline.
        result = await analyze(InputType.url, url=msg.media_url,
                               touchpoint=Touchpoint.whatsapp_bot)
    else:
        return BotReply(verdict="unknown", action="allow",
                        message="Send me a link or an APK file and I'll check it for you.")

    score = result.report.risk.score
    action = resolve_action(score, "whatsapp_bot")
    verdict = result.report.verdict.label.value
    return BotReply(verdict=verdict, action=action, message=_plain_language(verdict, action))


def _extract_url(text: str | None) -> str | None:
    if not text:
        return None
    import re

    m = re.search(r"https?://\S+", text)
    return m.group(0) if m else None
