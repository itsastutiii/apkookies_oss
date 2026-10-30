// APKookies Download Guard — MV3 service worker.
//
// Hooks APK download events, computes the SHA-256 of the downloaded bytes, and
// queries the fast hash-lookup endpoint. Based on the response it blocks / warns
// / allows.
//
// IMPORTANT LIMITATION (flagged as an architectural assumption in the root README):
//   The MV3 `downloads` API does NOT let an extension read the partially-written
//   file mid-stream, so true "block before the file finishes writing" is not
//   possible with the stock downloads API alone. Options:
//     (a) hash after completion and delete/quarantine if malicious (implemented
//         path below), or
//     (b) route downloads through a native-messaging helper / local proxy that
//         streams+hashes before commit (real "pre-write" block). TODO.

const API_BASE = "http://localhost:8000"; // TODO: configurable via options page

chrome.downloads.onCreated.addListener(async (item) => {
  if (!isApk(item)) return;
  // TODO(option b): signal a native host to intercept the stream here.
});

chrome.downloads.onChanged.addListener(async (delta) => {
  if (!delta.state || delta.state.current !== "complete") return;
  const [item] = await chrome.downloads.search({ id: delta.id });
  if (!item || !isApk(item)) return;

  try {
    const sha256 = await hashDownloadedFile(item);
    const verdict = await lookupHash(sha256);
    handleVerdict(item, verdict);
  } catch (err) {
    console.warn("APKookies check failed", err);
  }
});

function isApk(item) {
  const name = (item.filename || item.url || "").toLowerCase();
  return name.endsWith(".apk") || item.mime === "application/vnd.android.package-archive";
}

async function hashDownloadedFile(item) {
  // TODO: read the file bytes. MV3 SW cannot read arbitrary local files directly;
  // requires a native-messaging helper or downloading via fetch() for URLs.
  // Placeholder: hash the URL string so the flow is demonstrable.
  const buf = new TextEncoder().encode(item.url);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function lookupHash(sha256) {
  const resp = await fetch(`${API_BASE}/v1/hash/lookup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sha256, touchpoint: "browser_extension" }),
  });
  return resp.json(); // { known, verdict, action, matched_by, cluster_id }
}

function handleVerdict(item, verdict) {
  if (verdict.action === "block") {
    chrome.downloads.removeFile(item.id).catch(() => {});
    notify("Blocked dangerous APK", `${item.filename} was flagged as ${verdict.verdict}.`);
  } else if (verdict.action === "warn") {
    notify("Caution: risky APK", `${item.filename} may be unsafe.`);
  }
  // "allow" (incl. unknown) -> no action; backend may still run full analysis.
}

function notify(title, message) {
  chrome.notifications.create({
    type: "basic",
    iconUrl: "icon128.png",
    title,
    message,
  });
}
