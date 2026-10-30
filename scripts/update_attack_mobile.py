"""Regenerate data/mitre/attack-mobile.json from an official ATT&CK Mobile release.

Pinned source: MITRE's attack-stix-data repository (STIX 2.1). The output is a
compact extract (techniques with names/tactics/status, malware families with the
techniques MITRE documents for them) plus provenance: version, URL, SHA-256.

    python scripts/update_attack_mobile.py 20.0                  # downloads
    python scripts/update_attack_mobile.py 20.0 --file local.json  # offline

Update the pin deliberately (new version = review the diff of the output).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "mitre" / "attack-mobile.json"
URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
       "mobile-attack/mobile-attack-{version}.json")


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def extract(bundle: dict) -> tuple[dict, dict]:
    objs = bundle["objects"]
    by_stix = {o["id"]: o for o in objs}
    patterns = {o["id"]: o for o in objs if o["type"] == "attack-pattern"}
    names = {_attack_id(o): o["name"] for o in patterns.values()}

    techniques = {}
    for o in patterns.values():
        tid = _attack_id(o)
        if not tid:
            continue
        parent = tid.split(".")[0] if "." in tid else None
        techniques[tid] = {
            "name": o["name"],
            "full_name": f"{names.get(parent, parent)}: {o['name']}" if parent else o["name"],
            "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])],
            "subtechnique_of": parent,
            "deprecated": bool(o.get("x_mitre_deprecated")),
            "revoked": bool(o.get("revoked")),
        }

    malware = {}
    for o in objs:
        if o["type"] != "malware" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        sid = _attack_id(o)
        if sid:
            malware[sid] = {"name": o["name"], "aliases": sorted(set(o.get("x_mitre_aliases", [])) - {o["name"]}),
                            "techniques": set()}
    stix_to_sid = {o["id"]: _attack_id(o) for o in objs if o["type"] == "malware"}
    for o in objs:
        if (o["type"] == "relationship" and o.get("relationship_type") == "uses"
                and not o.get("revoked") and not o.get("x_mitre_deprecated")):
            sid = stix_to_sid.get(o["source_ref"])
            target = by_stix.get(o["target_ref"])
            if sid in malware and target and target["type"] == "attack-pattern":
                tid = _attack_id(target)
                if tid:
                    malware[sid]["techniques"].add(tid)
    for m in malware.values():
        m["techniques"] = sorted(m["techniques"])
    return dict(sorted(techniques.items())), dict(sorted(malware.items()))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("version", help="ATT&CK release, e.g. 20.0")
    ap.add_argument("--file", type=Path, help="use an already-downloaded STIX bundle")
    args = ap.parse_args()

    url = URL.format(version=args.version)
    raw = args.file.read_bytes() if args.file else urllib.request.urlopen(url, timeout=120).read()
    bundle = json.loads(raw)
    collection = next(o for o in bundle["objects"] if o["type"] == "x-mitre-collection")
    if collection.get("x_mitre_version") != args.version:
        raise SystemExit(f"bundle is version {collection.get('x_mitre_version')}, not {args.version}")
    techniques, malware = extract(bundle)
    out = {
        "attack_version": args.version,
        "domain": "mobile-attack",
        "source_url": url,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "source_modified": collection.get("modified"),
        "licence": "ATT&CK terms of use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/",
        "techniques": techniques,
        "malware": malware,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    active = sum(1 for t in techniques.values() if not (t["deprecated"] or t["revoked"]))
    print(f"Wrote {OUT}: {len(techniques)} techniques ({active} active), {len(malware)} malware")


if __name__ == "__main__":
    main()
