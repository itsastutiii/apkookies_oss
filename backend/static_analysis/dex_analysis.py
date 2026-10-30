"""One androguard bytecode analysis per sample, shared by all static passes.

Builds androguard's `Analysis` (classes, methods, strings, fields and the
cross-references between them) once from the DEX bytes, so API-usage and
anti-analysis detection can ask "is this API actually CALLED, and from where?"
instead of "does this text appear somewhere in the file?".

The DEX bytes come from common/apk_zip (same bytes the hashes are computed on).
If androguard is missing or the DEX can't be parsed, `analysis` is None and
`error` says why; callers must report that stage as unavailable, not as clean.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from backend.common import apk_zip

logger = logging.getLogger(__name__)


@dataclass
class DexIndex:
    dex_entries: list[tuple[str, bytes]] = field(default_factory=list)
    analysis: Optional[Any] = None   # androguard.core.analysis.analysis.Analysis
    error: Optional[str] = None
    _static_reads: Optional[dict[str, set[str]]] = field(default=None, repr=False)

    @property
    def available(self) -> bool:
        return self.analysis is not None

    def callers_of(self, class_desc: str, method_name: str) -> list[str]:
        """In-app call sites of an API method (exact class descriptor, method-name regex).

        Calls to an inherited framework method made through an in-app subclass
        (e.g. `performGlobalAction` inside a class extending AccessibilityService)
        are recorded by androguard against the subclass, so those count too.
        """
        dx = self.analysis
        classes = [class_desc, *self.subclasses_of(class_desc)]
        found: set[str] = set()
        for cls in classes:
            for m in dx.find_methods(classname=f"^{re.escape(cls)}$",
                                     methodname=f"^(?:{method_name})$"):
                for _, caller, _ in m.get_xref_from():
                    if not caller.is_external():
                        found.add(method_location(caller))
        return sorted(found)

    def string_users(self, strings: list[str]) -> dict[str, list[str]]:
        """{string: [methods that load it]} for EXACT code-referenced strings."""
        pattern = "^(?:" + "|".join(re.escape(s) for s in strings) + ")$"
        out: dict[str, list[str]] = {}
        for sa in self.analysis.find_strings(pattern):
            users = sorted({method_location(m) for _, m in sa.get_xref_from()})
            if users:
                out[sa.get_value()] = users
        return out

    def static_field_readers(self, class_desc: str, field_names: list[str]) -> list[str]:
        """In-app methods that read a static field, e.g. Landroid/os/Build;->FINGERPRINT.

        androguard doesn't track reads of framework (external) fields, so this
        scans sget instructions once per sample and caches the result.
        """
        if self._static_reads is None:
            self._static_reads = {}
            for m in self.analysis.find_methods(no_external=True):
                refs = {ins.get_output().split(", ", 1)[-1].split(" ", 1)[0]
                        for ins in m.get_method().get_instructions()
                        if ins.get_name().startswith("sget")}
                if refs:
                    self._static_reads[method_location(m)] = refs
        wanted = {f"{class_desc}->{name}" for name in field_names}
        return sorted(loc for loc, refs in self._static_reads.items() if refs & wanted)

    def strings_by_method(self, strings: list[str]) -> dict[str, set[str]]:
        """{method: {exact strings it loads}} -- for same-method co-occurrence rules."""
        by_method: dict[str, set[str]] = {}
        for value, users in self.string_users(strings).items():
            for loc in users:
                by_method.setdefault(loc, set()).add(value)
        return by_method

    def subclasses_of(self, class_desc: str) -> list[str]:
        """In-app classes whose direct superclass is `class_desc`."""
        return sorted(c.name for c in self.analysis.find_classes(no_external=True)
                      if c.extends == class_desc)


def build(source: str | Path | bytes, target_sdk: Optional[int] = None,
          dex_entries: Optional[list[tuple[str, bytes]]] = None) -> DexIndex:
    """Parse every DEX and build cross-references. Never raises."""
    entries = dex_entries if dex_entries is not None else apk_zip.read_dex_entries(source)
    if not entries:
        return DexIndex(entries, None, "no DEX files could be read")
    try:
        from androguard.core.analysis.analysis import Analysis
        from androguard.core.dex import DEX
    except ImportError:
        return DexIndex(entries, None, "androguard is not installed")
    try:
        dx = Analysis()
        for _, blob in entries:
            dx.add(DEX(blob, using_api=target_sdk))
        dx.create_xref()
        return DexIndex(entries, dx, None)
    except Exception as e:  # malformed/hostile DEX must not crash the pipeline
        logger.warning("DEX analysis failed: %r", e)
        return DexIndex(entries, None, f"DEX analysis failed: {type(e).__name__}")


def method_location(method_analysis) -> str:
    """'Lcom/x/Foo;->bar' for a calling method (for evidence/locations)."""
    return f"{method_analysis.class_name}->{method_analysis.name}"
