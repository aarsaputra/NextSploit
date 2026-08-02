#!/usr/bin/env python3
"""
NextSploit — CVE-2026-64641: DoS App Router via Server Actions CPU Exhaustion

Root Cause:
  Crafted requests targeting App Router applications with at least one Server
  Action cause excessive CPU usage, blocking processing of further requests.

Detection Strategy:
  1. Version-based check (primary — safest, no risk).
  2. Precondition: App Router + active Server Actions.
  3. Non-destructive response-time differential probe with a minimal crafted
     payload to detect if the endpoint is sensitive without triggering real DoS.

Affected Versions:
  >= 15.0.0, < 15.5.21  (branch 15.x)
  >= 16.0.0, < 16.2.11  (branch 16.x)
Fixed In       : 15.5.21 / 16.2.11
Severity       : High
"""

import time
import requests

from core.config import ScanConfig, CVE_DATABASE, check_vuln_status
from core.reporter import ModuleResult, Finding
from core.output import log_info, log_success, log_warning, log_debug, print_finding

CVE_ID   = "CVE-2026-64641"
CVE_INFO = CVE_DATABASE[CVE_ID]

# Craft a safe probe: multipart body that exercises the Server Action parser
# without sending enough tokens to actually exhaust CPU
_SAFE_PROBE_BODY = (
    b"--boundary\r\n"
    b"Content-Disposition: form-data; name=\"1_action\"\r\n\r\n"
    b"nextsploit-dos-probe\r\n"
    b"--boundary--\r\n"
)
_SAFE_PROBE_HEADERS = {
    "Content-Type": "multipart/form-data; boundary=boundary",
    "Next-Action": "nextsploit-dos-probe",
}

# Time ratio threshold: if probe takes > 3x the baseline, flag it
_TIME_RATIO_THRESHOLD = 3.0


def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(
        cve=CVE_ID,
        title=CVE_INFO["title"],
        severity=CVE_INFO["severity"],
        status="NOT VULNERABLE",
    )

    # Precondition: App Router
    if not config.has_app_router():
        result.status = "NOT_APPLICABLE"
        log_info(f"[{CVE_ID}] Pages Router detected — skipping.")
        return result

    # Precondition: at least one Server Action
    if not config.has_active_server_actions():
        result.status = "NOT_APPLICABLE"
        log_info(f"[{CVE_ID}] No Server Action IDs discovered — skipping.")
        return result

    session = config.create_session()
    target  = config.target.rstrip("/")

    log_info(f"Starting {CVE_ID} scan — DoS App Router Server Actions CPU exhaustion...")

    # Version check
    best_ver = config.version_state.best()
    version_detected = best_ver.value if best_ver else None
    version_vulnerable = False

    if version_detected:
        vuln_status = check_vuln_status(version_detected, CVE_ID)
        if vuln_status == "PATCHED":
            log_success(f"Version {version_detected} is patched for {CVE_ID}.")
            return result
        if vuln_status == "VULNERABLE":
            version_vulnerable = True
            log_warning(f"Version {version_detected} is in the vulnerable range.")

    # Use first discovered Action ID for probe target
    action_id = config.discovered_action_ids[0]
    action_url = f"{target}/"

    # Baseline timing (normal GET)
    try:
        t0 = time.monotonic()
        session.get(action_url, timeout=config.timeout)
        baseline_ms = (time.monotonic() - t0) * 1000
        log_debug(f"Baseline response time: {baseline_ms:.1f}ms")
    except requests.RequestException as e:
        log_debug(f"Baseline request failed: {e}")
        baseline_ms = 500.0

    # Probe timing (crafted SA request)
    probe_headers = {**_SAFE_PROBE_HEADERS, "Next-Action": action_id}
    probe_ms = None
    try:
        t0 = time.monotonic()
        r = session.post(
            action_url,
            data=_SAFE_PROBE_BODY,
            headers=probe_headers,
            timeout=config.timeout,
        )
        probe_ms = (time.monotonic() - t0) * 1000
        log_debug(f"SA probe response time: {probe_ms:.1f}ms | status={r.status_code}")
    except requests.Timeout:
        probe_ms = config.timeout * 1000
        log_warning(f"SA probe timed out after {config.timeout}s — possible CPU saturation.")
    except requests.RequestException as e:
        log_debug(f"SA probe request failed: {e}")

    time_anomaly = (
        probe_ms is not None
        and baseline_ms > 0
        and (probe_ms / baseline_ms) >= _TIME_RATIO_THRESHOLD
    )

    if version_vulnerable and time_anomaly:
        detail = (
            f"CONFIRMED: Next.js {version_detected} (vulnerable range) + Server Action "
            f"probe took {probe_ms:.0f}ms vs baseline {baseline_ms:.0f}ms "
            f"({probe_ms/baseline_ms:.1f}x ratio) — CPU exhaustion DoS signature detected."
        )
        confidence = 0.85
    elif version_vulnerable:
        detail = (
            f"Next.js {version_detected} is in the vulnerable range for {CVE_ID}. "
            f"Server Action endpoint exists but no timing anomaly detected. "
            "May be patched or load balancer absorbs timing signal."
        )
        confidence = 0.45
    elif time_anomaly:
        detail = (
            f"Server Action probe took {probe_ms:.0f}ms vs baseline {baseline_ms:.0f}ms "
            f"({probe_ms/baseline_ms:.1f}x). Version unconfirmed — vulnerable if < 15.5.21 or < 16.2.11."
        )
        confidence = 0.50
    else:
        log_success(f"No {CVE_ID} indicators detected.")
        return result

    evidence = {
        "detected_version": version_detected or "unknown",
        "action_id_probed": action_id,
        "baseline_ms": f"{baseline_ms:.1f}",
        "probe_ms": f"{probe_ms:.1f}" if probe_ms else "timeout",
        "remediation": "Upgrade to Next.js 15.5.21+ (15.x) or 16.2.11+ (16.x).",
    }
    log_warning(detail)
    print_finding(CVE_ID, detail, evidence)
    result.add_finding(Finding(
        cve=CVE_ID,
        severity=CVE_INFO["severity"],
        title="DoS App Router via Server Actions CPU Exhaustion",
        status="VULNERABLE",
        detail=detail,
        evidence=evidence,
        confidence=confidence,
    ))
    return result
