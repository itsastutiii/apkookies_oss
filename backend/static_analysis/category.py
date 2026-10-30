"""App-category resolution, shared by static analysis, scoring and training.

One function decides the category so that API "suspicion", the rules (R001,
R002), the knowledge graph and the features a model is trained on all see the
same value. Previously, static analysis used only the manifest's declared
category (which almost no app sets) while scoring used this keyword inference,
so R002 could practically never fire.

Order: the manifest's declared category, else a conservative keyword guess
from the package name and DEX strings, else None. The guess only emits a
category on a distinctive token, to avoid labelling arbitrary apps "Banking".

Known weakness: DEX strings are attacker-controlled. A Communication guess
exempts SMS use from R001, so planting "whatsapp" in a string table can buy
that exemption. A metadata-backed category (store listing) is future work.
"""
from __future__ import annotations

import re
from typing import Iterable, Optional

_MARKERS = {
    "Banking": ("bank", "banking", "wallet", "finance", "fintech", "upi", "bhim", "paytm", "paypal", "hdfc", "icici", "sbi", "axisbank", "kotak"),
    # No "sms" marker: SMS-stealing code contains "content://sms", which made the very
    # behaviour under judgement classify the app as Communication and exempt it.
    "Communication": ("whatsapp", "telegram", "messenger", "signal", "messaging", "chat", "wechat", "skype"),
    "SocialMedia": ("facebook", "instagram", "twitter", "snapchat", "tiktok", "social"),
    "Game": ("game", "unity3d", "unity", "unreal", "gaming"),
    "Wallpaper": ("wallpaper", "livewallpaper", "wallpapers"),
    "Productivity": ("calculator", "calendar", "notes", "notepad", "office", "docs", "todo", "productivity"),
}
_MAX_STRINGS = 5000


def resolve_category(declared: Optional[str], package_name: Optional[str],
                     dex_strings: Iterable[str]) -> tuple[Optional[str], str]:
    """Return (category, source) where source is declared | inferred | none."""
    if declared:
        return declared, "declared"
    strings = list(dex_strings)[:_MAX_STRINGS]
    text = " ".join([package_name or "", *strings]).lower()
    for category, markers in _MARKERS.items():
        if any(re.search(rf"(?<![a-z0-9]){re.escape(m)}(?![a-z0-9])", text) for m in markers):
            return category, "inferred"
    return None, "none"


def infer_category(bundle) -> Optional[str]:
    """Category of a StaticBundle: the one static analysis resolved, or (for bundles
    built by hand, e.g. in tests and demos) the same resolution done now."""
    if getattr(bundle, "category_source", None):
        return bundle.category
    manifest = bundle.structural.manifest
    return resolve_category(manifest.declared_category, manifest.package_name,
                            bundle.code_intel.dex_strings)[0]
