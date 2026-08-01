#!/usr/bin/env python3
"""
NextSploit — Centralized Version State

All scanner modules should call `config.report_version()` when they discover
a version signal. The orchestrator reads `config.version_state.best()` after
all modules have run to print the final Vulnerability Matrix.

Source priority (higher = more authoritative):
  buildid > header > chunk_js > error_leak > module_infer
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# Source strings accepted by report_version()
VALID_SOURCES = frozenset({
    "buildid",
    "header",
    "chunk_js",
    "error_leak",
    "module_infer",
})

_SOURCE_PRIORITY: dict[str, int] = {
    "buildid":      4,
    "header":       3,
    "chunk_js":     2,
    "error_leak":   1,
    "module_infer": 0,
}


@dataclass
class VersionSignal:
    """A single observed version evidence."""
    value:      str
    confidence: float   # 0.0 – 1.0
    source:     str     # one of VALID_SOURCES


@dataclass
class VersionState:
    """
    Thread-safe accumulator for version signals discovered across modules.

    Usage:
        config.report_version("14.2.35", 0.85, "chunk_js")
        best = config.version_state.best()
        if best:
            print(best.value)
    """
    signals: list[VersionSignal] = field(default_factory=list)
    _lock: object = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        import threading
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    def add(self, value: str, confidence: float, source: str) -> None:
        """Record a new version signal.  Safe to call from any thread."""
        if source not in VALID_SOURCES:
            raise ValueError(
                f"Unknown source {source!r}. Must be one of {sorted(VALID_SOURCES)}"
            )
        confidence = max(0.0, min(1.0, confidence))
        sig = VersionSignal(value=value.strip(), confidence=confidence, source=source)
        with self._lock:
            self.signals.append(sig)

    # ------------------------------------------------------------------
    def best(self) -> Optional[VersionSignal]:
        """
        Return the most authoritative version signal.

        Tie-breaking (in order):
          1. Highest confidence
          2. Higher source priority (`buildid` > `header` > …)
          3. Latest signal added (stable — avoids arbitrary ordering)
        """
        with self._lock:
            if not self.signals:
                return None
            return max(
                enumerate(self.signals),
                key=lambda iv: (
                    iv[1].confidence,
                    _SOURCE_PRIORITY.get(iv[1].source, -1),
                    iv[0],           # insertion order — last wins on full tie
                ),
            )[1]

    # ------------------------------------------------------------------
    def all_unique_versions(self) -> list[str]:
        """Return all distinct version strings seen, sorted descending."""
        with self._lock:
            seen: dict[str, float] = {}
            for s in self.signals:
                seen[s.value] = max(seen.get(s.value, 0.0), s.confidence)
        return sorted(seen, key=lambda v: seen[v], reverse=True)

    # ------------------------------------------------------------------
    @property
    def best_version(self) -> Optional[str]:
        sig = self.best()
        return sig.value if sig else None
