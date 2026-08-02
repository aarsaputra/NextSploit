"""
nextsploit/services/resource.py — Resource Manager implementing Circuit Breaker, rate limit, retries, and backoff.
"""

import time
import random
import threading
import requests
from typing import Any, Dict, Optional
from nextsploit.core.constants import Events
from nextsploit.core.logger import log_warning, log_error, log_info, log_debug


class CircuitBreakerOpenException(Exception):
    """Raised when the Circuit Breaker is open and blocking requests."""
    pass


class ResourceManagerSession(requests.Session):
    """
    Custom requests Session wrapped with resource controls:
    - Circuit Breaker (trips on consecutive errors/WAF blocks).
    - Rate Limiting (throttling requests).
    - Adaptive Retries with Exponential Backoff & Jitter.
    - Auto-emits event notifications to Event Bus.
    """

    def __init__(
        self,
        event_bus: Any,
        rate_limit: int = 5,       # requests per second
        max_retries: int = 3,
        backoff_factor: float = 1.0,
        cb_threshold: int = 5,     # consecutive failures to trip
        cb_recovery_time: float = 10.0 # seconds before half-open probe
    ):
        super().__init__()
        self.event_bus = event_bus
        self.rate_limit = rate_limit
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.cb_threshold = cb_threshold
        self.cb_recovery_time = cb_recovery_time

        # Circuit Breaker state
        self._cb_state = "CLOSED"  # CLOSED, OPEN, HALF-OPEN
        self._cb_lock = threading.Lock()
        self._consecutive_failures = 0
        self._last_state_change = time.monotonic()

        # Rate Limiting helper
        self._last_request_time = 0.0
        self._rate_limit_lock = threading.Lock()

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Override request method to wrap outgoing traffic with safety features."""
        # 1. Circuit Breaker Check
        self._check_circuit_breaker()

        # 2. Rate Limiting Throttling
        self._apply_rate_limit()

        # 3. Publish REQUEST_SENT event
        self.event_bus.publish(Events.REQUEST_SENT, {"url": url, "method": method})

        retries = 0
        start_time = time.monotonic()
        last_exception = None
        response = None

        while retries <= self.max_retries:
            try:
                # Handle timeout override from kwargs or default
                if "timeout" not in kwargs:
                    kwargs["timeout"] = 10

                log_debug(f"Sending HTTP {method} request to {url} (Attempt {retries + 1}/{self.max_retries + 1})")
                r_start = time.monotonic()
                response = super().request(method, url, **kwargs)
                r_duration = time.monotonic() - r_start

                # Analyze response for failures (WAF block or Server Error)
                is_err = response.status_code >= 500
                is_waf = self._is_waf_response(response)

                if is_err or is_waf:
                    self._handle_failure(is_waf)
                    if retries < self.max_retries:
                        self._apply_backoff(retries)
                        retries += 1
                        continue
                else:
                    self._handle_success()

                # Publish success response event
                self.event_bus.publish(Events.REQUEST_RECEIVED, {
                    "status_code": response.status_code,
                    "duration": r_duration,
                    "is_waf": is_waf
                })
                return response

            except (requests.RequestException, Exception) as e:
                last_exception = e
                self._handle_failure(is_waf=False)
                if retries < self.max_retries:
                    self._apply_backoff(retries)
                    retries += 1
                    continue
                break

        # If all retries failed
        duration = time.monotonic() - start_time
        self.event_bus.publish(Events.REQUEST_RECEIVED, {
            "status_code": 0,
            "duration": duration,
            "is_waf": False
        })

        if last_exception:
            log_error(f"HTTP Request failed after {retries} retries: {last_exception}")
            raise last_exception
        
        # Fallback empty response or return the last failed response
        if response is not None:
            return response
        raise requests.RequestException("Request failed with maximum retries reached.")

    def _check_circuit_breaker(self) -> None:
        """Trips, blocks, or transitions CB state based on timing and failures."""
        with self._cb_lock:
            if self._cb_state == "OPEN":
                elapsed = time.monotonic() - self._last_state_change
                if elapsed >= self.cb_recovery_time:
                    self._cb_state = "HALF-OPEN"
                    self._last_state_change = time.monotonic()
                    log_warning("Circuit breaker transitioned to HALF-OPEN. Probing target connectivity...")
                else:
                    log_error(f"Circuit breaker is OPEN. Request blocked to prevent target overload. (Remaining cooldown: {self.cb_recovery_time - elapsed:.1f}s)")
                    raise CircuitBreakerOpenException("Circuit Breaker is OPEN. Target is unresponsive or blocking.")

    def _handle_success(self) -> None:
        """Reset failures upon successful response."""
        with self._cb_lock:
            self._consecutive_failures = 0
            if self._cb_state == "HALF-OPEN":
                self._cb_state = "CLOSED"
                self._last_state_change = time.monotonic()
                log_info("Circuit breaker returned to CLOSED. Connection is healthy.")

    def _handle_failure(self, is_waf: bool) -> None:
        """Increment failure counter and check for trip conditions."""
        with self._cb_lock:
            self._consecutive_failures += 1
            reason = "WAF Block" if is_waf else "HTTP Error/Timeout"
            log_debug(f"Consecutive failures: {self._consecutive_failures}/{self.cb_threshold} (Reason: {reason})")
            
            if self._cb_state in ("CLOSED", "HALF-OPEN") and self._consecutive_failures >= self.cb_threshold:
                self._cb_state = "OPEN"
                self._last_state_change = time.monotonic()
                log_error("!!! CIRCUIT BREAKER TRIPPED !!! Target is blocked or offline. Entering cooling phase.")

    def _apply_rate_limit(self) -> None:
        """Applies rate-limiting delays between requests."""
        if self.rate_limit <= 0:
            return
        
        delay = 1.0 / self.rate_limit
        with self._rate_limit_lock:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            if elapsed < delay:
                sleep_time = delay - elapsed
                time.sleep(sleep_time)
            self._last_request_time = time.monotonic()

    def _apply_backoff(self, retry_count: int) -> None:
        """Applies exponential backoff with full jitter."""
        temp = self.backoff_factor * (2 ** retry_count)
        # Full jitter formula: sleep = random between 0 and temp
        sleep_time = random.uniform(0.0, temp)
        log_debug(f"Applying backoff delay of {sleep_time:.2f}s...")
        time.sleep(sleep_time)

    def _is_waf_response(self, r: requests.Response) -> bool:
        """Heuristic checks to see if response is a WAF blocking signature."""
        if r.status_code in (403, 429, 503):
            # Inspect body or headers for typical signs
            body = r.text.lower()
            headers = {k.lower(): v.lower() for k, v in r.headers.items()}
            
            # Common Cloudflare / Imperva / AWS WAF keywords
            waf_indicators = [
                "cloudflare", "cf-ray", "captcha-bypass", "security challenge",
                "incapsula", "sucuri", "mod_security", "blockpage", "ray id"
            ]
            
            if any(ind in body for ind in waf_indicators):
                return True
            if any(ind in headers.get("server", "") or ind in headers.get("cf-ray", "") for ind in waf_indicators):
                return True
        return False
