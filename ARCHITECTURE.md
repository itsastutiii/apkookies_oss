# APKookies architecture

How APKookies is put together: what each part does, how a request flows through the system, the design principles behind the scoring, and how mature each component is.

## Overview

APKookies receives an Android app (APK), or a link that leads to one, and answers one question: *is this app dangerous to a bank customer, and why?*

It first checks whether it has seen this exact file, or the same code, before. If it hasn't, it reads the app without running it (static analysis), turns the evidence into a risk score, and writes a report in which every finding is linked to evidence. Apps whose score is uncertain can also be run in an Android emulator (the sandbox) and re-scored.

## Request flow

```
 Clients (clients/)                          Backend API (backend/api, FastAPI, /v1/...)
 ──────────────────                          ─────────────────────────────────────────────
 WhatsApp bot (OpenWA) ──► /submit/apk, /jobs, /reports/{id}
 Analyst portal (React) ─► /reports/summaries, /reports/{id}, /jobs
 Analysts (token) ───────► /verdicts/{sha256}, …/override, …/clear
 Any client ─────────────► /submit/apk, /submit/url ──► orchestration/pipeline.analyze()

 pipeline.analyze()
   1. Ingest        ingestion/       URL → follow redirects (cloaking check) → detect the real file type
   2. Hash          hashing/         whole-file SHA-256/TLSH + decompressed DEX and manifest hashes
   3. Fast path     hashing/lookup   same file seen before (and its verdict still current)? /
                                     same or near-same code seen as malicious?
                                     ── hit ─► short report, done
   4. Static        static_analysis/ manifest, signing, one bytecode index (androguard) →
                                     app category → API calls (app code only), evasion checks,
                                     indicators, obfuscation, [Quark-Engine rules]
   5. Score         scoring/         base score (ML model or transparent weights) →
                                     rule weights → rule floors → verdict
                                     (every step recorded in risk.breakdown)
   6. Report        reporting/       evidence list, MITRE ATT&CK Mobile heatmap, explanation,
                                     recommendations   (threat_intel/: indicators, STIX export)
   7. Remember      hashing/verdict_store   SQLite: verdict + provenance for this exact file
   8. Sandbox       sandbox/         (async, if the score is uncertain) emulator + Frida + mitmproxy
                                     → re-score with runtime evidence → updated report
```

## Components

**Maturity.** *Stable:* implemented and covered by tests. *Experimental:* works, not yet evaluated at scale. *Prototype:* early version, not ready for use.

| Component | Where | What it does | Maturity |
|---|---|---|---|
| API | `backend/api/` | HTTP endpoints for all clients and the shared report format (`schemas/`). | Stable (no authentication or rate limiting yet) |
| Orchestrator | `backend/orchestration/pipeline.py` | Runs the steps above; the only place that calls the stages. | Stable |
| URL ingestion | `backend/ingestion/` | Redirect chain, cloaking check, file-type detection by content. | Stable for APKs; phishing-page analysis planned |
| Hashing and look-alikes | `backend/hashing/` | Whole-file MD5/SHA-256; SHA-256 and TLSH of the decompressed DEX code and manifest; similarity clusters. | Stable; similarity threshold to be calibrated |
| Verdict store | `backend/hashing/verdict_store.py`, `backend/common/provenance.py` | One verdict per file, with provenance (source, model and config hashes, scoring version, scoring mode). Re-checked when any of these change. Analyst override/clear with an append-only audit log. | Stable (single node) |
| Manifest and signing | `backend/static_analysis/manifest.py`, `structural.py`, `signing.py` | Permissions, components, certificates, debug certificates, bank allowlist check. | Stable |
| Bytecode index | `backend/static_analysis/dex_analysis.py` | One androguard cross-reference analysis per app, shared by the detectors. | Stable |
| API-usage detection | `backend/static_analysis/api_usage.py`, `libraries.py` | Which sensitive APIs the app's own code calls, and where. Calls inside common third-party libraries are excluded. | Stable |
| Anti-analysis detection | `backend/static_analysis/anti_analysis.py` | Emulator, debugger, root, timing and trigger checks, with locations. | Stable |
| Obfuscation signals | `backend/static_analysis/code_intel.py` | Entropy and byte-marker heuristics for packers, reflection and dynamic loading. | Heuristic |
| Indicator extraction | `backend/static_analysis/ioc_extraction.py` | Domains, URLs, IPs in a network context, Telegram bot tokens. | Stable |
| Quark-Engine rules | `backend/static_analysis/quark_rules.py` | Optional: 280 behaviour rules, including call-sequence and data-flow evidence ([docs/QUARK.md](docs/QUARK.md)). | Optional |
| App category | `backend/static_analysis/category.py` | Declared in the manifest, else inferred from package name and strings. | Experimental |
| Knowledge graph | `backend/scoring/knowledge_graph.py`, `data/knowledge_graph/` | Permissions → capabilities → MITRE techniques, plus category context. Every category edge cites a source. Shown as context; its score bonus is off by default. | Experimental |
| Models | `backend/scoring/rgcn.py`, `bayesian.py`, `aggregator.py`, `ml/models/` | R-GCN embedding, Bayesian prior and XGBoost, trained on CICMalDroid 2020. | Experimental |
| Scoring and rules | `backend/scoring/risk_score.py`, `modes.py`, `rules_engine.py` | Base score per scoring mode, then evidence-graded rules; every step is recorded in `risk.breakdown`. | Stable |
| Reporting and MITRE | `backend/reporting/` | Evidence list, ATT&CK Mobile heatmap with evidence strength, recommendations, explanation. | Stable |
| AI explanation | `backend/reporting/genai.py` | Gemini summary that must cite report evidence; otherwise a template is used. | Experimental |
| Threat intel | `backend/threat_intel/` | Indicator consolidation, certificate reuse, STIX 2.1 export. | Stable; enrichment planned |
| Sandbox | `backend/sandbox/` | Local Android emulator via adb, Frida hooks, mitmproxy, UI automation. | Experimental |
| Storage and jobs | `backend/common/storage.py`, `backend/orchestration/job_queue.py` | Reports as JSON files, verdicts in SQLite, an in-memory job queue. | Stable for single-node use |
| WhatsApp bot | `clients/whatsapp_bot/` | OpenWA webhook → full pipeline → plain-language reply, with sandbox follow-up. | Stable |
| Analyst portal | `clients/soc_portal/` | React UI: inbox, verdict and provenance, score breakdown, stages, MITRE heatmap, evidence, look-alikes. | Stable (no login yet) |
| Bank SDK | `clients/bank_sdk/` | Kotlin device-health check at login. | Prototype |
| Browser extension | `clients/browser_extension/` | Manifest V3 extension that checks APK downloads. | Prototype |
| Evaluation tools | `ml/eval/` | Labelled test-set evaluation, TLSH calibration, benign firing rates ([docs/TESTSET.md](docs/TESTSET.md)). | Stable |
| Training-data builder | `ml/data/build_androzoo_dataset.py` | Builds a balanced feature dataset from AndroZoo with the live analysis code ([docs/ANDROZOO.md](docs/ANDROZOO.md)). | Stable |

## Design principles

1. **Only an exact file match can say "benign".** Code-level and look-alike matches can only pass on "malicious". A repackaged bank app looks like the real one, so similarity must never vouch for an app. An analyst's "benign" override covers that exact file only.
2. **"Couldn't read it" is never "safe".** An unreadable manifest can't produce a benign verdict. Every stage reports `observed`, `heuristic`, `unavailable`, `failed` or `disabled` instead of silently returning nothing.
3. **Rules are only as strong as their evidence.** Rules work independently of the ML model, so a model error can't hide a known-bad pattern. But they are graded by evidence strength (below), and only decisive evidence can block on its own.
4. **A bank app's signing key is its identity.** A listed bank package name with any other certificate is blocked. A matching certificate is *not* used to lower the score.
5. **The app's own code, not its libraries.** Behaviour found only inside common SDKs (AndroidX, Google Play services, OkHttp, …) isn't attributed to the app.
6. **A verdict is only as current as the system that made it.** Stored verdicts carry their provenance and are re-checked after a model, configuration or scoring change. Analyst decisions don't expire.
7. **No real malware where it doesn't belong.** Real samples are analysed only on isolated machines, the sandbox runs without real internet access, and the repository contains no APKs.

## Evidence stages

Rules are graded using the five confidence stages of [Quark-Engine](https://github.com/quark-engine/quark-engine):

| Stage | Evidence | Provided by | Effect |
|---|---|---|---|
| 1 Permission | the manifest requests it | manifest parser | small weight (+0.05); never sets a minimum |
| 2 API call | the app's own code calls it | `api_usage.py` | larger weight (+0.10) |
| 3 Combination | the app's own code uses the combination | `api_usage.py` + rules | warn-level minimum (0.44: warn on every touchpoint, queue the sandbox) plus small weights for supporting signals |
| 4 Call sequence | the APIs are called in order | Quark-Engine (confidence 80%) | blocks if the behaviour is fraud-relevant (SMS, accessibility, overlay) |
| 5 Data flow | data flows between the calls, e.g. SMS text → network | Quark-Engine (confidence 100%) | blocks, same condition |

An app is blocked outright (score 0.90, no sandbox) only on:
- **an exact known-malicious file;**
- **R004:** a listed bank's package name signed with a different certificate;
- **R005:** fraud-relevant behaviour at stage 4 or 5.

`rules_engine.evaluate()` refuses a hard override from any other rule. A rule can also only become a hard override if it fires on fewer than 1% of benign apps; `ml/eval/benign_firing_rates.py` measures this.

| Rule | Evidence | Effect |
|---|---|---|
| R001 SMS read outside messaging apps | stage 1 / 2 / 3 | +0.05 / +0.10 / minimum 0.44 |
| R002 accessibility + overlay, with a supporting signal | stage 3 | minimum 0.44 (0.40 for a declared accessibility tool) + up to +0.10 |
| R002B accessibility + overlay alone | stage 1 / 3 | +0.05 / minimum 0.44 (0.40 for a declared accessibility tool) |
| R003 hardcoded Telegram bot token | indicator | minimum 0.40 |
| R004 bank package name, other certificate | identity | **block** |
| R004B bank app name, other package | identity | minimum 0.40 |
| R005 fraud behaviour at stage 4–5 | behaviour | **block** |

Order of the score steps: base score (model probability, or transparent weights in `rules` mode) → knowledge-graph bonus (off by default) → rule weights → rule minimums. Every step appears in `risk.breakdown` with how much it changed the score.

## Scoring modes and model evaluation

Set `scoring_mode` in `config/thresholds.yaml` (or `APKOOKIES_SCORING_MODE`), then restart the API:

| Mode | Base score |
|---|---|
| `model` (default) | The ML model: knowledge graph → R-GCN → Bayesian prior → XGBoost |
| `rules` | Transparent, hand-set weights over the same static evidence; no ML |
| `retrained` | Models trained on features extracted by this pipeline from real APKs (once available, in `ml/models/retrained/`) |

The current models were evaluated on a held-out split of CICMalDroid 2020 (`ml/results/metrics.json`):

| Model | ROC-AUC | Benign apps flagged | Malware missed |
|---|---|---|---|
| Permission-only XGBoost (baseline) | 0.988 | 51 / 270 | 20 / 1,470 |
| Full stack (R-GCN + Bayesian + XGBoost) | 0.981 | 18 / 270 | 90 / 1,470 |
| R-GCN alone | 0.926 | 69 / 270 | 37 / 1,470 |

At its threshold, the full stack raises far fewer false alarms than the permission baseline, at the cost of missing more malware. These figures come from a public, permission-based dataset with a small benign test set (270 apps). They are not a measure of performance on today's real-world banking apps and malware: that evaluation, and retraining on features from real APKs, are in progress.

## Roadmap

| Area | Today | Next |
|---|---|---|
| Training data | Models trained on CICMalDroid 2020 permission features | Retrain on features this pipeline extracts from a balanced, time-split AndroZoo sample (`ml/data/build_androzoo_dataset.py`) |
| Evaluation | Tooling for labelled test sets, TLSH calibration and benign firing rates | Published results on real banking apps and banking malware; calibrated thresholds |
| Behavioural evidence | Stage 4–5 from optional Quark-Engine rules | Built-in data-flow detection (e.g. SMS text → network) |
| Library detection | Package-prefix list | Code-based detection that survives renamed packages (LibScout-style) |
| Knowledge graph | Policy-sourced edges, shown as context | Edges derived from per-category data; re-evaluate the context bonus |
| Threat intel | Indicator extraction and STIX export | ThreatFox enrichment; on-request Telegram token liveness checks |
| Platform | Single node, shared analyst token | API authentication and rate limiting, persistent job queue, cloud sandbox option, Neo4j-backed graph |
| Clients | WhatsApp bot, analyst portal | Bank SDK and browser extension beyond prototype |
