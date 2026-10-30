# Building the AndroZoo training dataset

**What:** `ml/data/build_androzoo_dataset.py` downloads the ~4,000 APKs listed in `ml/data/androzoo/selection.csv` from [AndroZoo](https://androzoo.uni.lu/), extracts features with APKookies' own analysis code, deletes every APK straight after, and writes three small files: the training dataset.
**You need:** an AndroZoo API key. Keys are personal and granted by the AndroZoo team for research use. Set it only on the build machine, and never put it in git, chat, a file or a command line.
**Why a throwaway VM:** half of the APKs are malware. Run the build on a disposable cloud VM, never on a personal or work computer, and delete the VM at the end.
**Time:** under an hour of setup; the run itself takes several hours, unattended.

## AndroZoo rules (from its terms; the script enforces the technical ones)
- Research and non-commercial use only. Don't redistribute APKs: only the derived features are committed.
- At most 20 downloads at once (the script refuses more). 500,000 downloads per key in total; this run uses about 4,000 plus retries.
- The key expires about 6 months after approval. If downloads fail with `http_401`/`http_403`, check whether it has expired.

## 1. Create the VM
Any cloud works (Google Cloud, AWS, Azure). Use:
- **OS:** Ubuntu 22.04 LTS (ships Python 3.10, which the repo is pinned to).
- **Size:** 8 vCPUs, 32 GB RAM, 60 GB disk. Androguard can use 1–2 GB of RAM per large APK, and the script runs up to 7 analyses in parallel.
- **Network:** outbound internet only. No inbound ports except SSH, and SSH only with a key, not a password.
- **Nothing else on it:** no other credentials, no other data.

Connect with SSH. Everything below runs on the VM.

## 2. Install
```bash
sudo apt-get update && sudo apt-get install -y python3.10-venv python3-dev build-essential git tmux
git clone https://github.com/itsastutiii/apkookies_oss.git apkookies
cd apkookies
python3.10 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q tests/test_androzoo_builder.py
```
The tests must pass. They use fake downloads, not AndroZoo.

## 3. Check the selection (already in the repo)
The APKs to download were chosen from AndroZoo's public list and the list is in the repository, so you don't need the 4 GB list, and every run uses exactly the same apps. The sample is balanced: equal benign and malicious apps per year and per app store, one APK per package.
```bash
head -3 ml/data/androzoo/selection.csv
python3 -c "import json; d=json.load(open('ml/data/androzoo/selection.json')); print(d['selected'], d['apk_mb'])"
```
Expect `{'benign': 2000, 'malicious': 2000}` (or close; see `shortfall_per_class`) and roughly 40–50 GB of downloads in total, spread over time. The disk never holds more than 2 GB of APKs at once.

Some APKs may have been removed from AndroZoo since the selection was made. They show up as `download:http_404` failures; a few are fine.

## 4. (Optional) Choosing a different sample
To build a different sample, download AndroZoo's public list (`latest_with-added-date.csv.gz`, no key needed) and run `--select --list <list> --replace-selection` with your settings (`--per-class`, `--since`, `--until`, `--max-apk-mb`, detection thresholds, `--seed`; see `--help`). This needs no key and downloads no APKs. Don't change the selection during a run.

## 5. Set the key (only you, only here)
```bash
read -rs ANDROZOO_API_KEY && export ANDROZOO_API_KEY
```
Paste the key and press Enter. Nothing is shown, and it isn't saved in your shell history. Don't put it in a file, a script or a command-line argument; the builder only reads it from this variable. It's gone when you log out; repeat this step after reconnecting.

## 6. Run
Use `tmux` so the run survives a dropped SSH connection:
```bash
tmux new -s androzoo
read -rs ANDROZOO_API_KEY && export ANDROZOO_API_KEY      # inside tmux
.venv/bin/python ml/data/build_androzoo_dataset.py
```
Detach with `Ctrl-b d`; re-attach later with `tmux attach -t androzoo`. Progress is printed every 25 APKs.

**Stopping and resuming:** `Ctrl-c` stops it and deletes any temporary APKs. Running the **same command** again continues where it stopped; finished and failed apps are skipped. To retry the failed ones at the end, add `--retry-failed`.

**What it does with each APK:**
1. Download it into `~/apkookies-androzoo-work/apks/` and check its SHA-256.
2. Analyse it with the same code the live system uses.
3. Delete it immediately, even if the analysis failed.

## 7. Check the output
At the end it writes three files to `ml/data/androzoo/`, next to the selection:

| File | Contents |
|---|---|
| `features.jsonl.gz` | Per APK: label, dates, our extracted features, and what the current model says about it. |
| `samples.csv` | Per APK: sha256, label, VirusTotal detections, dates, market, status (`ok` / `failed:…`). Package names are hashed. |
| `DATASET.md` | Counts, date range, thresholds, exclusions, failures, code version. |

Then:
```bash
.venv/bin/python ml/data/build_androzoo_dataset.py --check
less ml/data/androzoo/DATASET.md
```
`--check` must print `OK to commit.` It checks:
- the three files are consistent with each other and with `selection.csv`;
- nothing else is in the folder;
- no file contains your key or a local file path.

In `DATASET.md`, check:
- **Extracted OK** is close to 2,000 per class. A few percent failures is normal: broken APKs, analysis timeouts.
- The failures are mostly `extract:…` rather than `download:…`.

Many `download:http_401` or `http_403` failures mean the key was rejected or has expired. Many `download:http_429` failures mean the server is limiting you: re-run later with `--concurrency 5`.

## 8. Keep only the three files
Copy `features.jsonl.gz`, `samples.csv` and `DATASET.md` off the VM (for example with `scp`). They contain derived features and hashes only, never APKs. AndroZoo's terms forbid redistributing its APKs, and the data is for research use only.

## 9. Delete the VM
In the cloud console, delete the VM **and its disk** (some clouds keep the disk unless you tick "delete boot disk"). Nothing from the VM should be kept: the work folder only holds the progress files and possibly a few temporary APKs.

## If something goes wrong
- **Out of memory / VM freezes:** re-run with `--extract-workers 3`.
- **Disk full:** check that `--temp-budget-gb` is the default (2) and that the disk is at least 60 GB.
- **"holds progress for a different selection.csv":** the selection changed since this run started (e.g. after a `git pull`). Use the original selection, or a new `--work-dir` for the new one.
- **Reporting a problem:** include the last 20 lines of output. The script never prints the key, but check anyway before sharing.
