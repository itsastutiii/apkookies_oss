# Building the bank allowlist

**What:** for each genuine bank app, record its package name, display name and the SHA-256 fingerprint of the certificate the bank signs it with, in `config/bank_allowlist.yaml`.
**Why:** a genuine bank app is always signed with the bank's own key. A fake or repackaged app can copy the package name, label and icon, but not the key. APKookies uses this list to flag:
- **R004 (block, score floor 0.90):** an app using a listed **package name** with any other certificate.
- **R004B (warn, score floor 0.40):** an app using a listed **app name** (different package) with another certificate. Weaker, because an unrelated app can share a name.

A matching certificate is shown as "genuine" in the report but does **not** lower the score. The repository ships with an empty list; until entries are added, both rules do nothing.

## Setup (once)
- The Android SDK with **platform-tools** (`adb`) and **build-tools** (`apksigner`). On Windows, `apksigner` is `%LOCALAPPDATA%\Android\Sdk\build-tools\<version>\apksigner.bat`.
- An emulator image **with Google Play** (Android Studio → Device Manager → a device showing the Play Store icon), or a spare test phone with USB debugging on. Sign in with a throwaway Google account.
- APKookies installed as in the README's Quick start.

## For each bank app
1. On the emulator/phone, open the **official** Play Store listing. Check the developer name is the bank itself (e.g. "Bank of India"), not a look-alike. Install.
2. Find the package name:
   ```
   adb shell pm list packages | grep -i <part-of-bank-name>      # Windows: findstr /i
   ```
3. Pull the installed APK. Modern apps may be split; you only need `base.apk`:
   ```
   adb shell pm path <package>
   adb pull /data/app/.../base.apk genuine.apk
   ```
4. Print the signing certificate(s):
   ```
   apksigner verify --print-certs genuine.apk
   ```
   Copy every line `Signer #N certificate SHA-256 digest: …`. Some apps have more than one signer or a rotated key; add them all.
5. Note the **display name** exactly as shown under the app icon.
6. Add an entry to `config/bank_allowlist.yaml` (replace `banks: []` with a list the first time):
   ```yaml
   banks:
     - bank: "Bank of India"
       packages: ["<package from step 2>"]
       app_names: ["<display name from step 5>"]
       cert_sha256:
         - "<64 hex characters from step 4>"
       source: "Play Store install, app version <x.y>, apksigner, 2026-11-01"
       collected_by: "<your name>"
   ```
   One bank can have several apps (retail, corporate, UPI). Either add each package to `packages`, or add separate entries.
7. Delete `genuine.apk` (only the fingerprint is needed), or keep it in your evaluation set outside the repository (`docs/TESTSET.md`).

## Check it
```
python scripts/check_bank_allowlist.py
```
It must print `OK`: it checks every fingerprint is 64 hex characters, every entry has a source and collector, and no package is claimed by two banks. Contributions of verified entries are welcome as pull requests that change only `config/bank_allowlist.yaml`.

## Keep it correct
- Only ever take certificates from the **official store install**, never from an APK someone forwarded.
- Re-check yearly or when a bank releases a new app. A key rotation shows up as an extra certificate in step 4.
- Exact matching only: `B0I Mobile` (zero) won't match `BOI Mobile`. Look-alike name detection is future work.
