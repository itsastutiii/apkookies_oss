# Evaluating APKookies on a labelled APK test set

The evaluation tools in `ml/eval/` run the real analysis pipeline on APKs you have labelled yourself and report how well it does: detection and false-alarm rates per touchpoint policy, how similar related apps' code is (to calibrate look-alike matching), and how often each rule fires on benign apps.

> **Safety:** a test set contains real malware. Keep it on a dedicated, isolated machine or VM, outside this repository, and never on a personal or work laptop. Don't install the malicious APKs on a phone. Keep the malware folder in a password-protected archive when you aren't using it.

## 1. Set up
Install APKookies as in the README's Quick start, then check it works without any APKs:
```bash
python -m pytest -q
python scripts/try_it_yourself.py
```
Section 1 of the tour should say `fuzzy hashing: available`. If it says `unavailable`, `py-tlsh` didn't build (it needs a C++ compiler: Xcode command-line tools on macOS, "Build Tools for Visual Studio" on Windows), and look-alike matching won't be measured.

Optional: install the Quark-Engine rules ([docs/QUARK.md](QUARK.md)) to include call-sequence and data-flow evidence.

## 2. Collect APKs, outside the repository
For example:
```
apk-testset/
  labels.csv
  benign/...
  malware/...
```
- **Benign (about half):** the genuine apps you care about most (for a bank: its own apps and other bank and UPI apps, installed from the official Play Store listing and pulled with `adb`; see [docs/BANK_ALLOWLIST.md](BANK_ALLOWLIST.md)), plus ordinary apps from other categories. Include messaging apps: they legitimately read SMS.
- **Malicious (about half):** known banking trojans, SMS/OTP stealers and fake bank apps from a malware repository such as MalwareBazaar (tags like `banker`, `FluBot`, `SpyNote`, `Anubis`, `Cerberus`), each with a public reference.
- **Useful edge cases:** two versions of the same app, a repackaged copy of a benign app, an app with a malformed manifest.

## 3. Write `labels.csv`
Start from `ml/eval/labels_template.csv`. One row per APK:

| column | meaning |
|---|---|
| `path` | path relative to `labels.csv`, e.g. `malware/flubot_1.apk` |
| `label` | `benign` or `malicious` (lowercase) |
| `group` | short tag, e.g. `bank_app`, `other_benign`, `banking_trojan`, `sms_stealer`, `fake_bank_app` |
| `family` | optional malware family (e.g. `flubot`), used to calibrate look-alike matching |
| `source` | optional; for your own record (not copied into results) |

Name files neutrally (`bank_01.apk`, `trojan_07.apk`), with no phone numbers or personal names in file names or groups.

## 4. Run
```bash
python ml/eval/evaluate_testset.py path/to/labels.csv --policy default
python ml/eval/summarize_testset.py
python ml/eval/calibrate_tlsh.py path/to/labels.csv
python ml/eval/benign_firing_rates.py --testset path/to/labels.csv
```
| Command | Writes (to `ml/results/testset/`) |
|---|---|
| `evaluate_testset.py` | `metrics.json` and `per_sample.csv`: hashes, labels, scores, actions and the code version that produced them; no file paths. Add `--scoring-mode rules` or `model` to compare modes. |
| `summarize_testset.py` | Checks those files for anything that shouldn't be shared (paths, long numbers) and writes `SUMMARY.md`. |
| `calibrate_tlsh.py` | `tlsh_calibration.json`: code-similarity distances for same-family pairs and for malware-vs-benign pairs, with a suggested match threshold. Advisory; the configuration isn't changed. |
| `benign_firing_rates.py --testset` | `benign_firing_rates.json`: how often each rule fires on benign vs malicious apps, at each evidence stage. A rule above ~1% on benign apps must not be a hard override. |

To describe your dataset alongside the results, copy `ml/results/testset/DATASET.md.template` to `DATASET.md` and fill it in.

**Never commit** APKs, `labels.csv`, or anything from your test-set folder.

## Troubleshooting
- `pip install` fails on `py-tlsh`: install a C++ compiler (above).
- A sample shows `not an APK`: it's still zipped, or isn't an APK.
- Many `analysis: ...` errors: note them in `DATASET.md`; they're useful findings.
- The runs are static analysis only. Sandbox evaluation is separate.
