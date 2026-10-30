# SOC Analyst Portal (React + TypeScript + Vite)

Internal dashboard over the backend's report API (`/v1/reports/*`, `/v1/jobs/*`).

**Works today**
- **Case inbox:** every stored report with its name, verdict, score and time, newest first (`GET /v1/reports/summaries`).
- **Verdict, severity and score**, with where the verdict came from (static / sandbox / analyst) and the scoring version.
- **Scoring mode** of the report (`rules` / `model` / `retrained`), with a tooltip saying what each means.
- **How the score was built:** every step of `risk.breakdown` (model, knowledge-graph bonus, rule minimums, remembered verdict), its change to the score and why. The steps add up to the score.
- **Analysis stages:** the decision path and each static-analysis stage's status (observed / heuristic / failed / unavailable / disabled) with the reason.
- **MITRE ATT&CK heatmap** by tactic, coloured by evidence strength (permission only < code calls the API < seen at runtime), with the pinned ATT&CK Mobile version.
- **Evidence ledger**, static findings (API use from bytecode, anti-analysis, permissions), hashes and look-alike matching (DEX-content hash, TLSH, family cluster, inherited verdict), analyst guidance.
- A report still in the sandbox refreshes itself every 5 s.

**Experimental / coming soon:** sandbox telemetry (experimental; needs the sandbox set up), the "Evidence analyst" Gemini page (experimental, needs `GEMINI_API_KEY`), Telegram token liveness (button is a stub), analyst login (coming soon; the verdict override API uses a shared token).

## Run locally (demo data, no real APKs)
From the repository root, in three terminals:
```
.venv/bin/uvicorn backend.api.main:app --port 8000
```
```
.venv/bin/python scripts/seed_demo_reports.py
```
```
cd clients/soc_portal && npm ci && npm run dev
```
Then open http://localhost:5173. The seed script submits three archives built from `tests/fixtures/dex/` (a suspicious one, a benign one, and a re-zipped copy of the suspicious one) through `POST /v1/submit/apk`. Running it again adds three more reports, answered from the verdict store.

Uncertain apps are queued for the sandbox. On a machine without an Android emulator set up, that step fails: the report then shows status `failed`, and the static verdict and score are kept.

The API base is `VITE_API_BASE` (default `http://localhost:8000`); the backend allows CORS from `localhost:5173`.

## Build check
`npm run build` (type-checks with `tsc`, then bundles).

## TODO
- Generate the `Report` types from `schemas/report.schema.json` (they're kept in step by hand in `src/api.ts`).
- Analyst login (SSO) and role-gating of override/clear.
