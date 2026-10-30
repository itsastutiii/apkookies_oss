# APKookies

**Explainable risk scoring for suspicious Android apps.**

APKookies analyses an Android app (APK), or a link that leads to one, and tells you whether it looks like banking fraud, how confident it is, and exactly why. It is built for the way fraud apps actually spread: as APK files sent over WhatsApp, SMS and messaging apps, outside the Play Store's review.

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)

---

## What it does

- **Recognises known apps and their copies.** Exact file hashes, hashes of the decompressed app code, and similarity hashing (TLSH) catch re-zipped, re-signed and lightly modified copies of known malware.
- **Reads the app without running it.** Static analysis of the manifest, signing certificates and bytecode: which sensitive APIs the app's *own* code calls (SMS, accessibility, screen overlays, device identifiers, WebView bridges), evasion checks (emulator, debugger, root, Frida detection), hardcoded indicators (domains, URLs, IPs, Telegram bot tokens) and obfuscation signals.
- **Spots fake bank apps.** Compares an app's package name and signing certificate against a list of genuine bank apps.
- **Scores the risk and shows its working.** Every report includes a step-by-step breakdown of how the score was built, so an analyst can see exactly which evidence moved it.
- **Maps findings to MITRE ATT&CK for Mobile,** with how strong the evidence is for each technique.
- **Remembers verdicts.** Known results are returned instantly, recorded with what produced them, re-checked when the scoring changes, and can be corrected by an analyst with an audit trail.
- **Meets people where they are.** A WhatsApp bot for the public and a web portal for security analysts, both on the same API.

## How it works

```
 APK or link
     │
     ▼
 1. Lookup          known file? same code? similar code?  ──► instant answer
     │ (not known)
     ▼
 2. Static analysis manifest · certificates · bytecode API calls · evasion checks · indicators
     │
     ▼
 3. Scoring         base score (ML model or transparent weights)
                    + rules graded by evidence strength
     │
     ├──► uncertain? ──► 4. Sandbox (optional): run in an Android emulator, re-score
     ▼
 5. Report          verdict · score breakdown · MITRE ATT&CK · evidence · advice
```

**Evidence-graded rules.** Rules only act as strongly as their evidence allows, following the five confidence stages used by [Quark-Engine](https://github.com/quark-engine/quark-engine):

| Evidence | Example | Effect on the score |
|---|---|---|
| Permission requested | the app asks for SMS access | small weight |
| API called by the app's own code | the app's code reads SMS | larger weight |
| Combination of APIs | accessibility service + screen overlay | raised to "warn", sent to the sandbox |
| Call sequence or data flow | SMS text read, then sent to a server | blocked |

Apps are blocked outright only on decisive evidence: a known-malicious file, a fake copy of a listed bank app (same package name, different certificate), or behaviour seen as a call sequence or data flow. Calls made inside common third-party libraries (AndroidX, Google Play services, OkHttp and others) are not counted as the app's own behaviour, so ordinary apps aren't flagged for what their SDKs do.

**Scoring modes.** The base score comes from one of:
- `model`: a machine-learning model (knowledge graph → R-GCN → Bayesian prior → XGBoost). This is the default.
- `rules`: transparent, hand-set weights over the same evidence, with no ML involved.
- `retrained`: models trained on features extracted from real APKs (coming soon).

Every report states which mode produced it. Switch modes in [`config/thresholds.yaml`](config/thresholds.yaml).

## Quick start

Requires Python 3.10+. Node.js 18+ is only needed for the analyst portal.

```bash
git clone https://github.com/itsastutiii/apkookies_oss.git
cd apkookies_oss
python3.10 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
```

On Windows, use `.venv\Scripts\pip` and `.venv\Scripts\python`. The similarity-hashing library (`py-tlsh`) compiles from source and needs a C++ compiler; without it, similarity matching is skipped and reported as unavailable.

**Run the tests**

```bash
.venv/bin/python -m pytest -q
```

**Take the 5-minute tour.** It walks through every feature using tiny, harmless test files that are compiled from source and never executed, so no real malware is needed:

```bash
.venv/bin/python scripts/try_it_yourself.py
```

**Start the API**

```bash
.venv/bin/uvicorn backend.api.main:app --port 8000
```

Interactive API docs are at http://localhost:8000/docs.

**Open the analyst portal with demo data**

```bash
.venv/bin/python scripts/seed_demo_reports.py      # submits three demo samples to the running API
cd clients/soc_portal && npm ci && npm run dev     # then open http://localhost:5173
```

## Usage

### Analyse an APK

```bash
curl -s -X POST -F "file=@app.apk" -F "touchpoint=api" http://localhost:8000/v1/submit/apk
```

The response contains:
- an `action`: `allow`, `warn` or `block`;
- the full `report`: verdict, score, `risk.breakdown`, MITRE ATT&CK techniques and evidence;
- a `sandbox_job_id` if the app was queued for dynamic analysis.

> **Handle real samples safely.** Analyse real or suspected malware only on a dedicated, isolated machine or VM, never on a personal or work laptop.

### Main API endpoints

| Endpoint | Purpose |
|---|---|
| `POST /v1/submit/apk` | Analyse an uploaded APK |
| `POST /v1/submit/url` | Follow a link (including redirects and cloaking checks) and analyse the APK it leads to |
| `POST /v1/hash/lookup` | Fast lookup of a known file hash |
| `GET /v1/reports/summaries` | List reports, newest first |
| `GET /v1/reports/{id}` | Full report |
| `GET /v1/reports/{id}/stix` | Indicators as a STIX 2.1 bundle |
| `GET /v1/jobs/{id}` | Status of a sandbox job |
| `GET /v1/verdicts/{sha256}`, `POST …/override`, `POST …/clear` | Analyst review of remembered verdicts (requires `ANALYST_TOKEN`) |

Responses follow a single shared report format, described in [`schemas/report.schema.json`](schemas/report.schema.json).

### Clients

| Client | What it does | Docs |
|---|---|---|
| WhatsApp bot | Users send an APK to a WhatsApp number and get back a plain-language verdict, the main reasons and advice. If a sandbox run is queued, a follow-up message is sent when it finishes. Built on the self-hosted [OpenWA](https://github.com/rmyndharis/OpenWA) gateway. | [`clients/whatsapp_bot`](clients/whatsapp_bot/README.md) |
| Analyst portal | Case inbox, verdicts, score breakdown, analysis stages, MITRE ATT&CK heatmap, evidence and look-alike matches. | [`clients/soc_portal`](clients/soc_portal/README.md) |

## Project status

**Supported**
- APK analysis pipeline, from hash lookup to report
- Static analysis from bytecode, with third-party library code excluded
- Evidence-graded scoring with a step-by-step breakdown, in `model` and `rules` modes
- Look-alike detection: exact code match and TLSH similarity
- MITRE ATT&CK for Mobile mapping
- Verdict store with provenance and analyst override
- WhatsApp bot and analyst portal
- STIX 2.1 export

**Experimental**
- **Sandbox:** runs apps in a local Android emulator with Frida instrumentation and traffic capture, then re-scores the report.
- **ML model:** trained on the public CICMalDroid 2020 permissions dataset. On that dataset it reaches a ROC-AUC of 0.98, but it hasn't yet been evaluated on recent real-world APKs.
- **AI explanations:** a plain-language summary that must cite the report's own evidence, with a fixed template as fallback. Needs a Gemini API key.
- **Optional Quark-Engine rules:** provide the call-sequence and data-flow evidence that can block an app.

## Coming soon

- **Retrained models** on features extracted by this pipeline from a large, balanced set of real APKs from [AndroZoo](https://androzoo.uni.lu/), evaluated on newer apps than they were trained on
- **Calibrated thresholds** from a labelled test set of real banking apps and banking malware
- **Built-in data-flow detection** (for example, SMS text sent over the network) without relying on Quark-Engine
- **Code-based third-party library detection,** robust to renamed packages
- **A knowledge graph grounded in data,** with category context learned from real apps
- **Threat-intel enrichment** (ThreatFox) and on-request Telegram bot-token liveness checks
- **Phishing-page analysis** for links that lead to web pages rather than APKs
- **Bank app SDK** (a device-health check at login) and a **browser extension** that checks APK downloads; both exist as early prototypes in [`clients/`](clients/)
- **API authentication** and rate limiting, a persistent job queue, and a cloud sandbox option

## Repository layout

```
backend/            FastAPI service and the analysis pipeline
  ├─ api/             HTTP endpoints
  ├─ hashing/         exact, code-content and similarity hashes; verdict store
  ├─ static_analysis/ manifest, certificates, bytecode, indicators, evasion checks
  ├─ scoring/         knowledge graph, ML models, rules, scoring modes
  ├─ sandbox/         emulator-based dynamic analysis (experimental)
  ├─ reporting/       report assembly, MITRE mapping, explanations
  └─ threat_intel/    indicator handling, STIX export
clients/            WhatsApp bot, analyst portal, bank SDK and browser extension prototypes
config/             thresholds, scoring mode, bank allowlist
data/               knowledge-graph ontology, MITRE ATT&CK Mobile data
ml/                 model training, evaluation and dataset tooling
schemas/            the shared report format (Pydantic + JSON Schema)
scripts/            demo, tour and maintenance scripts
tests/              test suite, with harmless DEX fixtures built from source
```

More detail on the design: [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Responsible use

APKookies is a defensive tool for malware analysis and fraud prevention. Only analyse apps you are authorised to analyse. Keep real malware on isolated machines, and run the sandbox without real internet access. The repository contains no APKs.

## Contributing

Issues and pull requests are welcome. Please run the test suite before opening a pull request, and never commit APKs, credentials, or data containing personal information.

## License and acknowledgements

- **Code:** [MIT](LICENSE). For third-party tools and services, see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
- **Quark-Engine** (GPL-3.0) is an optional runtime dependency and is not bundled.
- **MITRE ATT&CK®** is a registered trademark of The MITRE Corporation; the technique data in `data/mitre/` comes from MITRE's ATT&CK for Mobile.
- **CICMalDroid 2020** (Canadian Institute for Cybersecurity) is the training data for the current model.
- **AndroZoo** is the source of the upcoming training data. Model weights trained on AndroZoo data are for research use only, and the repository contains derived features, never AndroZoo's APKs. If you use them, please cite:
  - K. Allix, T. F. Bissyandé, J. Klein, Y. Le Traon. *AndroZoo: Collecting Millions of Android Apps for the Research Community.* MSR 2016. DOI [10.1145/2901739.2903508](https://doi.org/10.1145/2901739.2903508)
