"""Signing-certificate reuse across analysed samples.

Attackers often sign many fake apps with one key, so "this certificate also
signed N other samples, M of them malicious" is useful context for an analyst.
It is reported, NOT scored: a legitimate developer's key signs many benign apps,
and turning one wrong malicious verdict into a key-wide penalty would cascade.

In-memory MVP (like the hash store). TODO: persist with the hash repository.
"""
from __future__ import annotations

from collections import defaultdict


class CertReuseStore:
    def __init__(self) -> None:
        self._samples: dict[str, dict[str, str]] = defaultdict(dict)  # cert fp -> {sha256: verdict}

    def lookup(self, fingerprints: list[str], exclude_sha256: str | None = None) -> tuple[int, int]:
        """(other samples sharing any of these certs, how many of them malicious). Read-only."""
        others: dict[str, str] = {}
        for fp in fingerprints:
            for sha, verdict in self._samples.get(fp, {}).items():
                if sha != exclude_sha256:
                    others[sha] = verdict
        return len(others), sum(1 for v in others.values() if v == "malicious")

    def record(self, fingerprints: list[str], sha256: str, verdict: str) -> None:
        for fp in fingerprints:
            self._samples[fp][sha256] = verdict
