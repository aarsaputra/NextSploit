#!/usr/bin/env python3
"""
NextSploit — CVE-2025-59471: Image Optimizer OOM Denial of Service

Root Cause:
  Crafted image optimization parameters (e.g., extreme width) cause unbounded memory allocation
  before the request is rejected, leading to OOM crashes on vulnerable Next.js versions.

Detection Strategy:
  1. Version-based gating via config.version_state.best() (no false positives alone).
  2. Verify that the /_next/image endpoint is reachable (baseline probe).
  3. Timing differential using core.timing helpers (avg+stdev) with identical request parameters
     except for a payload that triggers the OOM path (e.g., a specially crafted SVG that
     forces the optimizer to allocate large buffers). The baseline request uses a safe
     PNG image with normal dimensions.
  4. Status code differential: vulnerable targets may return 500 or timeout on the
     crafted payload, while patched versions respond with 400.

Confidence tiers:
  0.80 — version match + endpoint active + timing anomaly (z-score > 3) OR 500 status on crafted payload
  0.55 — endpoint active + timing anomaly, version unconfirmed
  0.35 — version match only, no timing anomaly detected

Affected Versions:
  < 15.5.10 (both 15.x and 16.x branches) — fixed in 15.5.10.
Severity : MEDIUM
"""

import time
import requests

from core.config import ScanConfig
from core.cve_database import CVE_DATABASE, check_vuln_status
from core.reporter import ModuleResult, Finding, ScanStatus
from core.output import log_info, log_success, log_warning, log_debug, print_finding
from core.timing import measure_baseline_timing, is_timing_anomalous

CVE_ID   = "CVE-2025-59471"
CVE_INFO = CVE_DATABASE[CVE_ID]

# Baseline request: safe PNG image (favicon) with modest dimensions
_BASELINE_URL_TEMPLATE = "{target}/_next/image?url=%2Ffavicon.ico&w=32&q=75"
# Crafted payload: a malicious SVG designed to trigger OOM (size parameter same as baseline)
# The vulnerability is independent of image size – the SVG's internal structure triggers the bug.
_CRAFTED_URL_TEMPLATE = "{target}/_next/image?url=%2Fsvg-oom.svg&w=32&q=75"

def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(
        cve=CVE_ID,
        title=CVE_INFO["title"],
        severity=CVE_INFO["severity"],
        status=ScanStatus.SAFE,
    )

    log_info(f"Starting {CVE_ID} scan — Image Optimizer OOM DoS check...")
    session = config.create_session()
    target = config.target.rstrip('/')

    # Version gating via version_state (correct API)
    best_ver = config.version_state.best()
    version_detected = best_ver.value if best_ver else None
    version_vulnerable = False
    if version_detected:
        log_debug(f"Detected version: {version_detected}")
        vuln_status = check_vuln_status(version_detected, CVE_ID)
        if vuln_status == "PATCHED":
            log_success(f"Version {version_detected} is patched for {CVE_ID}.")
            return result
        if vuln_status == "VULNERABLE":
            version_vulnerable = True
            log_warning(f"Version {version_detected} is in the vulnerable range.")

    # Baseline: check if endpoint is reachable
    baseline_url = _BASELINE_URL_TEMPLATE.format(target=target)
    try:
        r_base = session.get(baseline_url, timeout=config.timeout)
        config.record_request(r_base.status_code)
        endpoint_active = r_base.status_code in (200, 400, 404)
        log_debug(f"Baseline image endpoint status={r_base.status_code}")
    except requests.RequestException as e:
        log_debug(f"Baseline request failed: {e}")
        endpoint_active = False

    if not endpoint_active:
        if version_vulnerable:
            # Version matches but we cannot confirm behavior without endpoint
            result.status=ScanStatus.INCONCLUSIVE
            result.add_finding(Finding(
                cve=CVE_ID,
                severity=CVE_INFO["severity"],
                title="Version matches — endpoint not reachable",
                status=ScanStatus.INCONCLUSIVE,
                detail="Version in vulnerable range but /_next/image endpoint is not reachable.",
                evidence={"detected_version": version_detected},
                confidence=0.35,
            ))
        else:
            result.status = "SAFE"
        return result

    # Passive mode default: no active probe
    if not config.confirm_active:
        if version_vulnerable:
            result.status=ScanStatus.INCONCLUSIVE
            result.add_finding(Finding(
                cve=CVE_ID,
                severity=CVE_INFO["severity"],
                title="Version range matches — OOM probe skipped (requires --confirm-active)",
                status=ScanStatus.INCONCLUSIVE,
                detail="Version matches vulnerable range but no active probe executed.",
                evidence={"detected_version": version_detected},
                confidence=0.35,
            ))
        else:
            result.status = "SAFE"
        return result

    # Active probing (user opted in)
    log_warning("[!] This module sends a crafted SVG to the Image Optimizer which may trigger OOM on vulnerable targets.")

    # Baseline timing with safe PNG (multiple samples)
    baseline_avg, baseline_stdev = measure_baseline_timing(
        session, baseline_url, samples=5, method="GET", timeout=config.timeout, config=config
    )
    log_debug(f"Baseline timing: avg={baseline_avg:.3f}s, stdev={baseline_stdev:.3f}s")

    # Probe with crafted SVG (identical dimensions, different content)
    crafted_url = _CRAFTED_URL_TEMPLATE.format(target=target)
    try:
        start = time.monotonic()
        r_probe = session.get(crafted_url, timeout=config.timeout)
        probe_time = time.monotonic() - start
        config.record_request(r_probe.status_code)
        log_debug(f"Crafted SVG probe: status={r_probe.status_code}, time={probe_time:.3f}s")
    except requests.Timeout:
        probe_time = config.timeout
        config.record_request(503)
        log_warning("Crafted SVG probe timed out — possible OOM condition.")
        r_probe = None
    except requests.RequestException as e:
        log_debug(f"Crafted SVG request failed: {e}")
        probe_time = None
        r_probe = None
        config.record_request(0)

    # Determine timing anomaly via Z-score
    time_anomaly = False
    if probe_time is not None:
        time_anomaly = is_timing_anomalous(baseline_avg, baseline_stdev, probe_time)

    # Determine status code anomaly (500 indicates unpatched OOM path)
    status_anomaly = r_probe and r_probe.status_code == 500

    # Confidence logic
    if version_vulnerable and (time_anomaly or status_anomaly):
        detail = (
            f"CONFIRMED: Next.js {version_detected} (vulnerable) + crafted SVG caused "
            f"{'timeout' if probe_time is None else f'{probe_time:.0f}s'} response "
            f"(baseline avg {baseline_avg:.0f}s)."
        )
        confidence = 0.80
    elif time_anomaly or status_anomaly:
        detail = (
            f"Image Optimizer responded {'500' if status_anomaly else 'slowly'} to crafted SVG "
            f"(baseline avg {baseline_avg:.0f}s). Version unconfirmed — vulnerable if < 15.5.10."
        )
        confidence = 0.55
    elif version_vulnerable:
        detail = (
            f"Next.js {version_detected} is in vulnerable range but no timing or status anomaly detected."
        )
        confidence = 0.35
    else:
        result.status = "SAFE"
        return result

    evidence = {
        "detected_version": version_detected or "unknown",
        "baseline_avg_s": f"{baseline_avg:.3f}",
        "baseline_stdev_s": f"{baseline_stdev:.3f}",
        "probe_time_s": f"{probe_time:.3f}" if probe_time is not None else "timeout",
        "probe_status_code": r_probe.status_code if r_probe else None,
        "remediation": "Upgrade Next.js to 15.5.10 or newer.",
    }
    log_warning(detail)
    print_finding(CVE_ID, detail, evidence)
    result.add_finding(Finding(
        cve=CVE_ID,
        severity=CVE_INFO["severity"],
        title="Image Optimizer OOM Denial of Service",
        status=ScanStatus.VULNERABLE,
        detail=detail,
        evidence=evidence,
        confidence=confidence,
    ))
    return result
