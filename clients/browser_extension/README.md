# Browser Extension — APK Download Guard (Manifest V3)

> **Status: coming soon (skeleton).** What exists today: it notices APK downloads and calls `POST /v1/hash/lookup`, then removes the file or notifies on block/warn. It does **not** hash the downloaded file yet (it hashes the URL as a placeholder), so it can't recognise a real APK; blocking before the download finishes needs a native helper (not built).

Hooks APK download events, hashes the file client-side, and queries the fast
`POST /v1/hash/lookup` endpoint to block / warn / allow.

## ⚠️ Architectural assumption (please confirm)
The stock MV3 `downloads` API cannot read a partially-written file, so a true
*"block before the file finishes writing"* is not achievable with the downloads
API alone. Two options are stubbed in `background.js`:
- **(a) post-completion hash + quarantine/delete** — works with pure MV3.
- **(b) native-messaging helper / local proxy** — enables real pre-write blocking.

I implemented path (a) and left TODOs for (b). Let me know which you want as the
primary UX.

## Config
Set `API_BASE` (currently `http://localhost:8000`) via the options page (TODO).
