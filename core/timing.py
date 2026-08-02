#!/usr/bin/env python3
"""
NextSploit — Core Timing Statistics Helpers
"""

import time
import statistics
import requests

def measure_baseline_timing(session, url, samples=5, method="GET", data=None, headers=None, timeout=10, config=None, **kwargs):
    """
    Measure response times for a target URL over multiple samples.
    Returns (avg, stdev).
    """
    times = []
    for _ in range(samples):
        try:
            start = time.monotonic()
            if method.upper() == "POST":
                r = session.post(url, data=data, headers=headers, timeout=timeout, **kwargs)
            else:
                r = session.get(url, headers=headers, timeout=timeout, **kwargs)
            elapsed = time.monotonic() - start
            times.append(elapsed)
            if config:
                config.record_request(r.status_code)
        except requests.RequestException:
            if config:
                config.record_request(503)
            # Do not append failed requests to timing stats to avoid distorting baseline
            pass
            
    if not times:
        return 0.0, 0.0
        
    avg = statistics.mean(times)
    stdev = statistics.stdev(times) if len(times) > 1 else 0.0
    return avg, stdev

def is_timing_anomalous(baseline_avg, baseline_stdev, observed_time, z_threshold=3.0):
    """
    Return True if the observed_time is an anomaly based on Z-score or 3x threshold fallback.
    """
    if baseline_avg <= 0:
        return False
    if baseline_stdev <= 0:
        # Fallback if standard deviation is 0
        return observed_time > (baseline_avg * 3.0)
    z_score = (observed_time - baseline_avg) / baseline_stdev
    return z_score > z_threshold
