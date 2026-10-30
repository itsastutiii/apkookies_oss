# APKookies WhatsApp Bot (OpenWA)

A FastAPI webhook receiver for
[OpenWA](https://github.com/rmyndharis/OpenWA), a self-hosted WhatsApp
gateway. OpenWA is a separate third-party service (MIT-licensed); see
`THIRD_PARTY_NOTICES.md`.

A user sends an APK to the linked WhatsApp number as a document. The bot
submits it to the **full APKookies pipeline** and replies in plain
language with the analysis result.

## What it does

1.  Refuses APKs larger than 50 MiB. The size is checked using
    WhatsApp's metadata before downloading and checked again after
    download.
2.  Immediately replies: `APK received, analysing`.
3.  Downloads the APK from OpenWA **in memory** (the bot does not write
    the APK to disk) and submits it to the backend's
    `POST /v1/submit/apk` endpoint with the `whatsapp_bot` touchpoint.
    The backend performs hash lookup, static analysis, knowledge-graph
    processing, rule evaluation, scoring, and MITRE ATT&CK mapping.
4.  Replies with the verdict, risk score, advice from the server-side
    allow/warn/block policy, the top reasons from `risk.breakdown`, and
    the MITRE ATT&CK techniques.
5.  If the backend queues a sandbox run, the bot tells the user, polls
    `GET /v1/jobs/{id}`, and sends an update when the sandbox finishes.
    If the sandbox fails or times out, the bot explains that the initial
    result still stands.

Only APK documents are supported. Forwarded links are not handled yet.

## Architecture and deployment

The bot, APKookies backend, and OpenWA are separate services:

-   **OpenWA** manages the WhatsApp session and delivers incoming
    message events to the bot's webhook.
-   **WhatsApp bot** receives webhook events, downloads APK documents
    through OpenWA, calls the APKookies backend, and sends replies.
-   **APKookies backend** runs the analysis pipeline and exposes the API
    used by the bot.

**Run the bot and backend on a dedicated, isolated machine, not a
personal laptop.** Anyone who has the WhatsApp number can send it a
potentially malicious APK, and any sandbox execution also takes place in
your analysis environment. Do not expose the backend, OpenWA dashboard,
or bot ports publicly unless you have secured them appropriately.

## Setup

### 1. Requirements

-   Python 3.10+
-   Node.js and npm
-   Git
-   A WhatsApp account to link with OpenWA
-   The APKookies repository and its required backend dependencies

The commands below use Windows PowerShell. Adjust paths and activation
commands for your operating system.

### 2. Download and start OpenWA

Clone OpenWA into a separate directory:

``` powershell
git clone https://github.com/rmyndharis/OpenWA.git
cd OpenWA
npm ci
npm run dev
```

When OpenWA starts, open its dashboard:

``` text
http://localhost:2886
```

Keep the OpenWA process running.

### 3. Create and connect a WhatsApp session

1.  Open the OpenWA dashboard.
2.  Create a session named `apk-bot`.
3.  In WhatsApp on your phone, go to **Linked devices → Link a device**.
4.  Scan the QR code shown by OpenWA.
5.  Wait until the session status indicates that it is connected and
    ready.

### 4. Configure the OpenWA webhook

Configure the webhook for the `apk-bot` session:

-   **Webhook URL:** `http://127.0.0.1:9000/webhook`
-   **Event:** `message.received`

Save the configuration and make sure the event subscription is enabled.

The `127.0.0.1` address assumes OpenWA and the bot are running on the
same machine. If they run on different machines, replace it with the bot
machine's reachable private-network address and ensure the relevant
firewall rules allow the connection.

### 5. Configure the APKookies environment

From the APKookies repository root, create or edit the `.env` file:

``` env
OPENWA_URL=http://localhost:2785
OPENWA_API_KEY_FILE=Z:/OpenWA/data/.api-key
APKOOKIES_API_URL=http://localhost:8000

BOT_LOG_WEBHOOKS=true
BOT_LOG_DIR=webhook_logs

BOT_SANDBOX_POLL_SECONDS=20
BOT_SANDBOX_TIMEOUT_SECONDS=1800
BOT_ANALYSIS_TIMEOUT_SECONDS=900
```

Update `OPENWA_API_KEY_FILE` to the actual location of the `.api-key`
file created by your OpenWA installation. Update `OPENWA_URL` if OpenWA
is listening on a different host or port. The example assumes OpenWA's
API is available at port `2785`.

`BOT_LOG_WEBHOOKS=true` is useful during initial setup and debugging
because it saves incoming webhook payloads under `webhook_logs`. These
payloads may contain personal information, including chat details.
Disable this setting after debugging if you do not need the logs:

``` env
BOT_LOG_WEBHOOKS=false
```

Do not commit `.env`, API keys, WhatsApp session data, or webhook logs.

### 6. Create the Python environment and install dependencies

From the APKookies repository root:

``` powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

Install the repository's dependencies using its dependency file, if
present. For example:

``` powershell
pip install -r requirements.txt
```

If the repository does not provide a dependency file for the bot,
install the bot's core packages:

``` powershell
pip install fastapi uvicorn httpx
```

The backend may require additional packages and services. Install and
configure all dependencies documented for the APKookies backend before
starting it.

### 7. Start all required services

Keep the following three services running in separate terminals.

**Terminal 1 --- OpenWA**

``` powershell
cd Z:\OpenWA
npm run dev
```

Use the actual directory where you cloned OpenWA.

**Terminal 2 --- APKookies backend**

From the APKookies repository root:

``` powershell
.\.venv\Scripts\Activate.ps1
python -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
```

Start any additional services required by your backend or sandbox
configuration as well.

**Terminal 3 --- WhatsApp bot**

From the APKookies repository root:

``` powershell
.\.venv\Scripts\python.exe -m uvicorn clients.whatsapp_bot.main:app --host 127.0.0.1 --port 9000 --env-file .env
```

The bot's webhook is now available at:

``` text
http://127.0.0.1:9000/webhook
```

For a deployment where OpenWA or the backend runs on another machine,
update the corresponding environment variable and webhook URL to use a
reachable address. Do not use `127.0.0.1` to refer to a different
machine.

## Verify the setup

### 1. Check the bot health endpoint

In PowerShell:

``` powershell
Invoke-RestMethod http://localhost:9000/health
```

The endpoint should return a healthy response.

### 2. Test WhatsApp messaging

From another WhatsApp account, send `hi` to the number linked to the
`apk-bot` session. The bot should reply with a greeting.

### 3. Test APK analysis

Send a valid `.apk` file to the linked number using WhatsApp's
**Document** attachment option.

-   Maximum supported APK size: **50 MiB**
-   Send the APK as a document, not as a photo or video.
-   The bot should acknowledge receipt, then reply with the analysis
    result.
-   If a sandbox run is queued, the bot should send a follow-up update
    when it completes.

## Run

Once OpenWA and the backend are configured and running, the two FastAPI
services can be started with:

``` powershell
# APKookies backend
python -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000

# WhatsApp bot
python -m uvicorn clients.whatsapp_bot.main:app --host 127.0.0.1 --port 9000 --env-file .env
```

Point the OpenWA webhook to `http://127.0.0.1:9000/webhook` when OpenWA
and the bot are on the same machine. Settings for the OpenWA URL and
API-key file, backend URL, webhook logging, and sandbox polling are
configured through environment variables; see the bot section of
`.env.example`.

## Troubleshooting

  -----------------------------------------------------------------------
  Problem                             What to check
  ----------------------------------- -----------------------------------
  No WhatsApp reply                   Confirm the OpenWA session is
                                      connected, the webhook URL is
                                      correct, and `message.received` is
                                      enabled. Check that the bot is
                                      running and reachable from OpenWA.

  `FileNotFoundError`                 Verify that `OPENWA_API_KEY_FILE`
                                      points to the actual `.api-key`
                                      file.

  Webhook returns `200 OK`, but no    Inspect the bot terminal output
  reply arrives                       and, if enabled, the files in
                                      `webhook_logs`. Confirm that the
                                      OpenWA API URL and API key are
                                      correct.

  APK analysis fails                  Confirm the APKookies backend is
                                      running and reachable at
                                      `APKOOKIES_API_URL` on port `8000`.
                                      Check backend logs for the
                                      underlying error.

  APK is rejected                     Confirm that the file is a valid
                                      APK document and does not exceed 50
                                      MiB.

  Sandbox update does not arrive      Check backend job status and logs.
                                      Review `BOT_SANDBOX_POLL_SECONDS`
                                      and `BOT_SANDBOX_TIMEOUT_SECONDS`.
  -----------------------------------------------------------------------

## Privacy and security

-   WhatsApp chat IDs are phone numbers. The bot logs only their last
    four digits.
-   APK downloads are held in memory by the bot; the bot does not write
    the downloaded APK to disk.
-   Raw webhook payloads are saved only when `BOT_LOG_WEBHOOKS=true`, in
    the configured `BOT_LOG_DIR` (git-ignored). They may contain
    personal information. Disable logging when it is no longer needed,
    and do not commit or share these files.
-   Never commit `.env`, API keys, WhatsApp session data, or webhook
    logs to GitHub.
-   Run the bot and backend in a dedicated, isolated environment. Treat
    every submitted APK as potentially malicious.

## Tests

Run the WhatsApp bot tests from the APKookies repository root:

``` powershell
pytest tests/test_whatsapp_bot.py
```

The test uses the real backend in-process, a mocked OpenWA service, and
the fixture APK built from `tests/fixtures/dex/suspicious.dex`.
