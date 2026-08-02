#!/usr/bin/env python3
"""
core/killswitch.py — Global safety governor for production target scanning.

Enforces request budgets, duration limits, finding limits, and filters
dangerous or unwanted module classes (e.g. CPU/Memory DoS, Cache Mutation, OOB).
"""

import time
import threading
from typing import Optional, Set

# Dangerous module groups for --skip-dos and safety controls
DOS_MODULES = {
    "55184", "67779", "23870", "23864", "64641",
    "64646", "64644", "64648", "64647", "59471", "mg66"
}
CACHE_MUTATING_MODULES = {"64648", "64647", "46982"}
OOB_MODULES = {"57822", "64645", "64649", "34351"}


class KillSwitch:
    """Thread-safe global execution safety governor."""

    def __init__(
        self,
        max_requests: Optional[int] = None,
        max_duration: Optional[float] = None,
        max_findings: Optional[int] = None,
        skip_modules: Optional[Set[str]] = None,
        skip_dos: bool = False,
    ):
        self._lock = threading.Lock()
        self.request_count = 0
        self.finding_count = 0
        self.start_time = time.time()
        self.max_requests = max_requests if (max_requests and max_requests > 0) else None
        self.max_duration = max_duration if (max_duration and max_duration > 0) else None
        self.max_findings = max_findings if (max_findings and max_findings > 0) else None
        
        self.skip_modules = set(skip_modules or [])
        if skip_dos:
            self.skip_modules.update(DOS_MODULES)

        self.aborted = False
        self.abort_reason = ""

    def allow_module(self, module_id: str) -> bool:
        """Check whether a module is permitted to execute under current safety rules."""
        if self.aborted:
            return False

        if module_id in self.skip_modules:
            return False

        if self.max_duration and (time.time() - self.start_time) > self.max_duration:
            with self._lock:
                self.aborted = True
                self.abort_reason = f"Max duration limit reached ({self.max_duration}s)"
            return False

        return True

    def count_request(self) -> bool:
        """
        Record a request execution.
        Returns False if request budget is exhausted (callers should abort module).
        """
        with self._lock:
            if self.aborted:
                return False

            if self.max_duration and (time.time() - self.start_time) > self.max_duration:
                self.aborted = True
                self.abort_reason = f"Max duration limit reached ({self.max_duration}s)"
                return False

            if self.max_requests and self.request_count >= self.max_requests:
                self.aborted = True
                self.abort_reason = f"Max requests budget reached ({self.max_requests})"
                return False

            self.request_count += 1
            return True

    def count_finding(self) -> bool:
        """
        Record a finding.
        Returns False if finding limit is reached.
        """
        with self._lock:
            self.finding_count += 1
            if self.max_findings and self.finding_count >= self.max_findings:
                self.aborted = True
                self.abort_reason = f"Max findings limit reached ({self.max_findings})"
                return False
            return True

    @property
    def summary(self) -> dict:
        """Return execution summary status."""
        return {
            "requests": self.request_count,
            "findings": self.finding_count,
            "elapsed_s": round(time.time() - self.start_time, 1),
            "aborted": self.aborted,
            "abort_reason": self.abort_reason,
        }
