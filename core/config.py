#!/usr/bin/env python3
"""
NextSploit — Scan Configuration & Context Management
"""

import time
import hashlib
import threading
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Any

# Maintain backward compatibility by re-exporting database and helper
from core.cve_database import CVE_DATABASE, check_vuln_status


# ─── Rate Limiter ─────────────────────────────────────────────────────────────

class RateLimiter:
    """
    Token bucket rate limiter.
    Call `acquire()` before each HTTP request to honour --rate-limit.
    Thread-safe.
    """

    def __init__(self, max_per_second: float):
        self._lock = threading.Lock()
        self._max = max_per_second
        self._tokens = max_per_second
        self._last = time.monotonic()

    def acquire(self) -> None:
        if self._max <= 0:
            return  # no limit
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(self._max, self._tokens + elapsed * self._max)
            if self._tokens < 1:
                sleep_time = (1 - self._tokens) / self._max
                time.sleep(sleep_time)
                self._tokens = 0
            else:
                self._tokens -= 1


# ─── Scan Configuration ────────────────────────────────────────────────────────

@dataclass
class ScanConfig:
    """Global scan configuration passed to all modules."""
    target: str
    timeout: int = 10
    threads: int = 10
    verbosity: int = 0            # 0=normal, 1=verbose, 2=extra verbose
    user_agent: str = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    )
    proxy: Optional[str] = None
    verify_ssl: bool = True
    output_file: Optional[str] = None
    output_dir: str = "reports"
    cve_list: list = field(default_factory=list)
    scan_all: bool = False

    # — Fingerprint context (populated by fingerprint module) —
    discovered_build_id: Optional[str] = None
    discovered_action_ids: list = field(default_factory=list)
    discovered_js_chunks: list = field(default_factory=list)
    discovered_css_chunks: list = field(default_factory=list)
    detected_router_type: Optional[str] = None  # "app" | "pages" | None
    last_response_headers: dict = field(default_factory=dict)  # Main page headers captured during fingerprinting

    # — Browser exploit integration (AnonKryptiQuz chaining) —
    browser_exploit: bool = False
    waf_bypass: bool = False

    # — Active-mode opt-in (modules that touch external hosts or shared cache) —
    confirm_active: bool = False  # --confirm-active flag

    # — Rate-limiting —
    delay: float = 0.0          # seconds between requests (--delay)
    rate_limit: int = 0         # max requests/second (--rate-limit); 0 = no limit

    # — Raw evidence logging (--save-responses) —
    save_raw_responses: Optional[str] = None   # None | "all" | "blocked-only" | "findings-only"
    raw_dir: Optional[Path] = field(default=None, init=False, repr=False, compare=False)
    current_module_id: Optional[str] = None    # Active module ID set during execution

    # — Private: initialized in __post_init__ —
    _counter_lock: object = field(default=None, init=False, repr=False, compare=False)
    _blocked_requests: int = field(default=0, init=False, repr=False, compare=False)
    _total_requests: int = field(default=0, init=False, repr=False, compare=False)
    _raw_evidence_count: int = field(default=0, init=False, repr=False, compare=False)
    _block_categories: dict = field(default_factory=dict, init=False, repr=False, compare=False)
    _rate_limiter: object = field(default=None, init=False, repr=False, compare=False)
    _version_state: object = field(default=None, init=False, repr=False, compare=False)
    _session: Optional[Any] = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._counter_lock = threading.Lock()
        self._blocked_requests = 0
        self._total_requests = 0
        self._raw_evidence_count = 0
        self._block_categories = {}
        self._rate_limiter = RateLimiter(self.rate_limit)
        self._session = None
        from core.version_state import VersionState
        self._version_state = VersionState()

    # ─── Version State ─────────────────────────────────────────────────────────────

    @property
    def version_state(self):
        return self._version_state

    def report_version(self, value: str, confidence: float, source: str) -> None:
        """
        Report a discovered Next.js version signal from any module.
        Thread-safe. The orchestrator reads config.version_state.best() at the
        end of the scan to determine the authoritative version.
        """
        self._version_state.add(value, confidence, source)

    # ─── Request Counters (thread-safe) ────────────────────────────────────────────────

    def record_request(self, status_code: int, response=None) -> None:
        """
        Record the outcome of one HTTP request. Call this after every
        requests.get/post inside a module so the orchestrator can compute
        noise_ratio and determine if the result is INCONCLUSIVE.
        """
        with self._counter_lock:
            self._total_requests += 1
            if status_code in (403, 429, 503):
                self._blocked_requests += 1
                if response is not None:
                    try:
                        from core.waf_detect import classify_blocked_response
                        category = classify_blocked_response(response)
                        self._block_categories[category] = self._block_categories.get(category, 0) + 1
                    except Exception:
                        pass

    def noise_ratio(self) -> float:
        """Fraction of blocked responses (0.0 – 1.0). Thread-safe."""
        with self._counter_lock:
            if self._total_requests == 0:
                return 0.0
            return self._blocked_requests / self._total_requests

    def block_category_summary(self) -> str:
        """
        Human-readable breakdown of blocked response categories.
        """
        with self._counter_lock:
            if not self._block_categories or self._blocked_requests == 0:
                return ""
            parts = [
                f"{round(count / self._blocked_requests * 100)}% {cat}"
                for cat, count in sorted(self._block_categories.items(), key=lambda x: -x[1])
            ]
            return ", ".join(parts)

    def total_request_count(self) -> int:
        """Total requests made in the current module window. Thread-safe."""
        with self._counter_lock:
            return self._total_requests

    def raw_evidence_count(self) -> int:
        """Count of raw evidence files saved for the current module. Thread-safe."""
        with self._counter_lock:
            return self._raw_evidence_count

    def reset_request_counters(self) -> None:
        """Reset per-module counters. Called by the orchestrator between modules."""
        with self._counter_lock:
            self._blocked_requests = 0
            self._total_requests = 0
            self._raw_evidence_count = 0

    # ─── Precondition Helpers ──────────────────────────────────────────────────────────

    def has_active_server_actions(self) -> bool:
        """True if the fingerprint phase discovered at least one Server Action ID."""
        return bool(self.discovered_action_ids)

    def has_discovered_assets(self) -> bool:
        """True if at least one JS or CSS chunk was discovered during fingerprinting."""
        return bool(self.discovered_js_chunks) or bool(self.discovered_css_chunks)

    def has_app_router(self) -> bool:
        """True if the fingerprint phase identified the target as an App Router app."""
        if self.detected_router_type is None:
            return True   # uncertain — do not skip the module
        return self.detected_router_type == "app"

    def has_managed_hosting(self) -> bool:
        """True if response headers indicate managed Vercel hosting."""
        headers = self.last_response_headers or {}
        header_keys_lower = {str(k).lower() for k in headers.keys()}
        vercel_markers = {"x-vercel-cache", "x-vercel-id", "x-vercel-signature"}
        if any(marker in header_keys_lower for marker in vercel_markers):
            return True
        server_header = str(headers.get("server", "")).lower()
        if "vercel" in server_header:
            return True
        return False

    # ─── Rate-Limiting Helper ───────────────────────────────────────────────────────────

    def throttle(self) -> None:
        """Call before each outbound HTTP request to honour delay/rate-limit."""
        if self.delay > 0:
            time.sleep(self.delay)
        self._rate_limiter.acquire()

    # ─── Proxies ────────────────────────────────────────────────────────────────────────────

    @property
    def proxies(self) -> Optional[dict]:
        if self.proxy:
            return {"http": self.proxy, "https": self.proxy}
        return None

    # ─── Raw Transaction Logging (--save-responses) ──────────────────────────────────────────

    def init_raw_dir(self, domain: str) -> None:
        """Create the per-domain raw evidence directory."""
        self.raw_dir = Path(f"reports/{domain}/raw")
        self.raw_dir.mkdir(parents=True, exist_ok=True)

    def log_transaction(
        self,
        module_id: str,
        request_obj,
        response_obj,
        label: str = "",
        is_finding: bool = False,
    ) -> Optional[str]:
        """
        Save raw HTTP request + response to disk when --save-responses is active.
        """
        if not self.save_raw_responses or self.raw_dir is None:
            return None

        status = getattr(response_obj, "status_code", 0)
        is_blocked = status in (403, 429, 503)

        if self.save_raw_responses == "blocked-only" and not is_blocked:
            return None
        if self.save_raw_responses == "findings-only" and not is_finding:
            return None

        try:
            req = request_obj
            req_line = f"{req.method} {req.url}\n"
            req_headers = "\n".join(f"{k}: {v}" for k, v in req.headers.items())
            req_body = (req.body or b"") if isinstance(req.body, bytes) else (req.body or "")
            if isinstance(req_body, bytes):
                req_body = req_body.decode("utf-8", errors="replace")

            resp_line = f"HTTP {status} {getattr(response_obj, 'reason', '')}\n"
            resp_headers = "\n".join(f"{k}: {v}" for k, v in response_obj.headers.items())
            
            import re
            # Redact request body if sensitive tokens present
            req_body = re.sub(
                r'(Authorization|Cookie|Set-Cookie|X-Auth-Token|api_key|token|password)[:\s=]+[^\n"&]{5,200}',
                r'\1: [REDACTED]',
                req_body, flags=re.IGNORECASE,
            )

            # Redact response body
            resp_body = response_obj.text[:50000]
            body_patterns = [
                (re.compile(r'(Authorization|Cookie|Set-Cookie|X-Auth-Token)[:\s]+[^\n"]{5,200}', re.I), r'\1: [REDACTED]'),
                (re.compile(r'"(session|token|access_token|refresh_token|api_key)"\s*:\s*"[^"]*"', re.I), r'"\1": "[REDACTED]"'),
                (re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+'), '[REDACTED_EMAIL]'),
                (re.compile(r'\b(?:eyJ[A-Za-z0-9_-]+\.){2}[A-Za-z0-9_-]+\b'), '[REDACTED_JWT]'),
            ]
            for pattern, replacement in body_patterns:
                resp_body = pattern.sub(replacement, resp_body)

            # Cache confusion warning check
            active_mod = module_id or self.current_module_id or "unknown"
            header_prefix = ""
            if any(cid in str(active_mod) for cid in ("64648", "64647")):
                header_prefix = (
                    "[!] WARNING: This CVE class involves cross-user data leakage. Review this\n"
                    "    file manually before attaching to any bug bounty report — automated\n"
                    "    redaction may not catch all sensitive data patterns.\n\n"
                )

            transaction = (
                f"{header_prefix}=== REQUEST ===\n{req_line}{req_headers}\n\n{req_body}\n\n"
                f"=== RESPONSE ===\n{resp_line}{resp_headers}\n\n{resp_body}\n"
            )

            fname_hash = hashlib.sha256(transaction.encode()).hexdigest()[:8]
            safe_mod = active_mod.replace("CVE-2026-", "").replace("CVE-2025-", "").replace("CVE-", "")
            safe_label = label or "req"
            fname = f"{safe_mod}_{safe_label}_{fname_hash}.txt"
            path = self.raw_dir / fname
            path.write_text(transaction, encoding="utf-8")

            with self._counter_lock:
                self._raw_evidence_count += 1

            return str(path)
        except Exception:
            return None

    def save_response(self, filename: str, response) -> str:
        """Save full HTTP response (status, headers, body) to output_dir."""
        import os
        os.makedirs(self.output_dir, exist_ok=True)
        filepath = os.path.join(self.output_dir, filename)
        try:
            with open(filepath, "w", encoding="utf-8", errors="ignore") as f:
                f.write(f"HTTP/1.1 {response.status_code} {response.reason}\n")
                for k, v in response.headers.items():
                    f.write(f"{k}: {v}\n")
                f.write("\n")
                f.write(response.text)
            return filepath
        except Exception:
            return ""

    # ─── Session Factory ────────────────────────────────────────────────────────────

    def create_session(self):
        """
        Get or create the cached NextSploitSession instance.
        """
        if self._session is None:
            from core.session import create_session
            self._session = create_session(self)
        return self._session

    def close(self) -> None:
        """Close the unified HTTP session."""
        if self._session is not None:
            self._session.close()
            self._session = None
