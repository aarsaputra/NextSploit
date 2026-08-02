#!/usr/bin/env python3
"""
core/timing.py — Robust timing differential engine for DoS / delay modules.

Uses median + percentile + Mann-Whitney U test (scipy optional) so CDN
and network latency noise don't produce false positives.
"""

import time
import statistics
from typing import List, Dict, Any, Optional

try:
    from scipy.stats import mannwhitneyu  # type: ignore
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False


class TimingProbe:
    def __init__(self, session, url: str, samples: int = 7, timeout: float = 60.0):
        self.session = session
        self.url = url
        self.samples = samples
        self.timeout = timeout

    def measure(self, headers: Optional[dict] = None, body: Optional[bytes] = None, method: str = "GET") -> List[float]:
        latencies = []
        for _ in range(self.samples):
            t0 = time.monotonic()
            try:
                if method.upper() == "GET":
                    self.session.get(self.url, headers=headers, timeout=self.timeout)
                else:
                    self.session.post(self.url, headers=headers, data=body, timeout=self.timeout)
                latencies.append(time.monotonic() - t0)
            except Exception:
                # Timeout or transport failure counts as max latency signal
                latencies.append(self.timeout)
            time.sleep(0.2)
        return latencies


def analyze_timing(base_lat: List[float], test_lat: List[float], threshold_x: float = 3.0) -> Dict[str, Any]:
    """Compare baseline vs test latency distributions."""
    if not base_lat or not test_lat:
        return {"verdict": "INCONCLUSIVE", "reason": "Insufficient latency samples"}

    b_med = statistics.median(base_lat)
    t_med = statistics.median(test_lat)
    ratio = (t_med / b_med) if b_med > 0 else float("inf")

    p_value = None
    if HAS_SCIPY and len(base_lat) >= 3 and len(test_lat) >= 3:
        try:
            _, p_value = mannwhitneyu(test_lat, base_lat, alternative="greater")
        except Exception:
            p_value = None

    verdict = "VULNERABLE" if (ratio >= threshold_x and (p_value is None or p_value < 0.05)) else "SAFE"

    return {
        "baseline_median": round(b_med, 3),
        "test_median": round(t_med, 3),
        "ratio": round(ratio, 2),
        "p_value": p_value,
        "samples": {"base": len(base_lat), "test": len(test_lat)},
        "verdict": verdict,
        "note": f"Ratio {round(ratio, 2)}x (threshold {threshold_x}x)"
    }
