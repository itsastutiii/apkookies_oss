"""Telegram bot-token liveness check (SOC portal feature — low priority / outline).

When a hardcoded Telegram bot token is extracted from a sample, call Telegram's
public getMe endpoint to check whether the C2 channel is still live. A 200 with
`ok: true` means the bot (and thus the campaign's exfil channel) is active.

CAUTION: this contacts the real Telegram API and reveals that the token is being
probed. Gate behind explicit SOC-analyst opt-in; never auto-run in bulk.

TODO: rate-limit + audit-log every probe; consider using getMe only, never
sending messages.
"""
from __future__ import annotations

from dataclasses import dataclass

import httpx

from config.settings import get_settings


@dataclass
class TokenLiveness:
    token_suffix: str      # last 6 chars only — never log the full token
    live: bool
    bot_username: str | None = None


async def check_token(token: str) -> TokenLiveness:
    """Probe a single bot token via getMe. Returns liveness (never raises)."""
    endpoint = get_settings().telegram_getme_endpoint.format(token=token)
    suffix = token[-6:]
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(endpoint)
            data = resp.json()
    except (httpx.HTTPError, ValueError):
        return TokenLiveness(token_suffix=suffix, live=False)

    if resp.status_code == 200 and data.get("ok"):
        return TokenLiveness(
            token_suffix=suffix,
            live=True,
            bot_username=data.get("result", {}).get("username"),
        )
    return TokenLiveness(token_suffix=suffix, live=False)
