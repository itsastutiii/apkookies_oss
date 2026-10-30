# WhatsApp bot (OpenWA)

FastAPI webhook receiver for [OpenWA](https://github.com/rmyndharis/OpenWA), a self-hosted WhatsApp gateway (MIT, run separately; see `THIRD_PARTY_NOTICES.md`).
A user sends an APK as a WhatsApp document; the bot runs it through the **full APKookies pipeline** and replies in plain language.

## What it does
1. Refuses APKs over 50 MiB (checked from WhatsApp's size before downloading, and again after).
2. Replies at once: "APK received, analysing".
3. Downloads the APK from OpenWA **in memory** (it is never written to disk by the bot) and submits it to the backend's `POST /v1/submit/apk` (touchpoint `whatsapp_bot`): hash lookup, static analysis, knowledge graph, rules, scoring, MITRE mapping.
4. Replies with the verdict, risk score, advice (from the server-side allow/warn/block policy), the top reasons from `risk.breakdown`, and the MITRE ATT&CK techniques.
5. If the backend queued a sandbox run, it says so, polls `GET /v1/jobs/{id}`, and sends an update when the sandbox finishes (or says the first result stands if it fails or times out).

APK documents only. Forwarded links are not handled yet (coming soon).

## Where to run it
**Run the bot and backend on a dedicated, isolated machine**, not a personal laptop: anyone who has the number can send it a real, malicious APK, and the sandbox (if used) runs there.

## Run
```
uvicorn backend.api.main:app --port 8000                                   # the backend
uvicorn clients.whatsapp_bot.main:app --port 9000 --env-file .env          # the bot
```
Point OpenWA's webhook at `http://<bot host>:9000/webhook`. Settings (OpenWA URL and API-key file, backend URL, sandbox polling) are environment variables; see the bot section of `.env.example`.

Privacy: chat IDs are phone numbers. The bot logs only their last 4 digits. Raw webhook payloads are saved only if `BOT_LOG_WEBHOOKS=true` (folder `BOT_LOG_DIR`, git-ignored); don't commit or share them.

## Tests
`pytest tests/test_whatsapp_bot.py`: the real backend in-process, a mocked OpenWA, and the fixture APK built from `tests/fixtures/dex/suspicious.dex`.
