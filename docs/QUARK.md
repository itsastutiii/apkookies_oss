# Optional: Quark-Engine behaviour rules

[Quark-Engine](https://github.com/quark-engine/quark-engine) scores Android behaviours ("send SMS", "read call log", "use accessibility to click") by checking each rule in five steps: permission → first API → both APIs → call sequence → data flow between the calls. APKookies reports matches at ≥ 80% confidence (call sequence or data flow) as evidence in the report. A fraud-relevant match (SMS, accessibility or overlay behaviour) at that level is the strongest behavioural evidence APKookies accepts: rule R005 blocks the app. Without Quark, APKookies' own analysis provides evidence up to the "combination of APIs" stage, which warns and sends the app to the sandbox but never blocks on its own.

## Licence
Quark is **GPL-3.0**. APKookies (MIT) only imports it at runtime as an optional extra; no Quark code or rules are copied into this repository. The rules repository has no licence file, so its rules aren't vendored either: fetch them yourself.

## Install (pinned versions)
```
pip install -e ".[quark]"     # quark-engine==26.10.1 (requires androguard 4.1.4, already pinned)
git clone https://github.com/quark-engine/quark-rules
git -C quark-rules checkout 514c21ca43e1cd41c51c72054d3b5581c59e1f0f   # 2026-10-24, 280 rules
```
Then in `.env`:
```
QUARK_RULES_DIR=/path/to/quark-rules/rules
QUARK_MIN_CONFIDENCE=80
```
Leave `QUARK_RULES_DIR` empty to disable Quark; the report then says `quark: disabled` with the reason.

## Notes
- Importing Quark creates `~/.quark-engine/` in your home folder (Quark's own config), and each run writes a dated `YYYY-MM-DD.quark.log` into the current folder (git-ignored).
- Runtime grows with APK size (all 280 rules run). Measure it on your own samples before enabling it on a latency-sensitive touchpoint.
- Tests: `tests/test_quark.py` always checks the disabled/not-installed paths. The real-rules tests run only when quark-engine is installed and `QUARK_RULES_DIR` is set.
