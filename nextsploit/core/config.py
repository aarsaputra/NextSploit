"""
nextsploit/core/config.py — Centralized configuration settings for NextSploit v4.
"""

import time
import threading
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

from nextsploit.core.constants import DEFAULT_TIMEOUT, DEFAULT_THREADS, DEFAULT_USER_AGENT


class RateLimiter:
    """
    Token bucket rate limiter.
    Thread-safe implementation for limiting requests per second.
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


@dataclass
class ScanConfig:
    """Global configuration parsed from command line and policy profiles."""
    target: str = ""
    target_file: Optional[str] = None
    policy_name: str = "safe"  # safe | bugbounty | pentest | ci
    timeout: int = DEFAULT_TIMEOUT
    threads: int = DEFAULT_THREADS
    verbosity: int = 0
    user_agent: str = DEFAULT_USER_AGENT
    proxy: Optional[str] = None
    verify_ssl: bool = True
    output_file: Optional[str] = None
    output_dir: str = "reports"
    cve_list: List[str] = field(default_factory=list)
    scan_all: bool = False

    # Evasion and browser settings
    browser_exploit: bool = False
    waf_bypass: bool = False
    confirm_active: bool = False

    # Authentication options
    auth_cookie: Optional[str] = None
    auth_token: Optional[str] = None
    auth_json: Optional[str] = None
    auth_probe_url: str = "/api/me"

    # Rate limiting & scheduling
    delay: float = 0.0
    rate_limit: int = 0
    timing_mode: bool = False

    # Safety limits
    skip_dos: bool = True
    max_requests_per_module: int = 0
    max_duration: float = 0.0
    max_findings: int = 0
    noise_threshold: float = 0.8

    # Dynamic findings and state populated during scanning (legacy compatibility)
    discovered_build_id: Optional[str] = None
    discovered_action_ids: List[str] = field(default_factory=list)
    discovered_js_chunks: List[str] = field(default_factory=list)
    discovered_css_chunks: List[str] = field(default_factory=list)
    detected_router_type: Optional[str] = None
    last_response_headers: Dict[str, Any] = field(default_factory=dict)

    # Internal state counters
    _total_requests: int = 0
    _blocked_requests: int = 0

    def __post_init__(self):
        self._rate_limiter = RateLimiter(self.rate_limit)
        self._counter_lock = threading.Lock()
        
        # Instantiate legacy VersionState structure if needed
        try:
            from core.version_state import VersionState
            self._version_state = VersionState()
        except ImportError:
            self._version_state = None

    def throttle(self) -> None:
        """Rate limit throttling helper."""
        if self.delay > 0:
            time.sleep(self.delay)
        self._rate_limiter.acquire()

    def record_request(self, status_code: int, response=None) -> None:
        """Increment request counters for performance metrics."""
        with self._counter_lock:
            self._total_requests += 1
            if status_code in (403, 429, 503):
                self._blocked_requests += 1

    def report_version(self, value: str, confidence: float, source: str) -> None:
        """Record version signal mapping."""
        if self._version_state is not None:
            self._version_state.add(value, confidence, source)

    def noise_ratio(self) -> float:
        """Fraction of blocked responses (0.0 – 1.0)."""
        with self._counter_lock:
            if self._total_requests == 0:
                return 0.0
            return self._blocked_requests / self._total_requests

    @property
    def version_state(self):
        return self._version_state

