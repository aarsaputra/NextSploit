#!/usr/bin/env python3
"""
NextSploit — CVE-2024-34350: HTTP Request Smuggling Check
"""

import time
import requests
from core.config import ScanConfig
from core.cve_database import CVE_DATABASE, check_vuln_status
from core.reporter import ModuleResult, Finding, ScanStatus
from core.output import log_info, log_success, log_warning, log_debug, print_finding
from core.timing import measure_baseline_timing, is_timing_anomalous

CVE_ID = "CVE-2024-34350"
CVE_INFO = CVE_DATABASE[CVE_ID]

# Smuggling payload: ambiguous Transfer-Encoding and Content-Length headers
_SMUGGLING_HEADERS = {
    "Transfer-Encoding": "chunked",
    "Content-Length": "0",
    "Connection": "keep-alive",
}

def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(
        cve=CVE_ID,
        title=CVE_INFO["title"],
        severity=CVE_INFO["severity"],
        status=ScanStatus.SAFE,
    )

    # Precondition: version check (used as initial filter only)
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
            log_warning(f"Version {version_detected} is in vulnerable range.")

    # Passive mode default: no active smuggling probe
    if not config.confirm_active:
        if version_vulnerable:
            result.status=ScanStatus.INCONCLUSIVE
            result.add_finding(Finding(
                cve=CVE_ID,
                severity=CVE_INFO["severity"],
                title="Version range matches — smuggling probe skipped (requires --confirm-active)",
                status=ScanStatus.INCONCLUSIVE,
                detail="Version matches vulnerable range but no active probe executed.",
                evidence={"detected_version": version_detected},
                confidence=0.35,
            ))
        else:
            result.status = "SAFE"
        return result

    # Active probing (user explicitly opted in)
    log_warning("[!] This module sends an HTTP request with ambiguous Transfer-Encoding and Content-Length headers which may affect intermediate proxies or load‑balancers.")
    session = config.create_session()
    target = config.target.rstrip('/')
    endpoint = target + "/"

    # Baseline timing using a normal GET request (multiple samples)
    baseline_avg, baseline_stdev = measure_baseline_timing(
        session, endpoint, samples=5, method="GET", timeout=config.timeout, config=config
    )
    log_debug(f"Baseline GET timing: avg={baseline_avg:.3f}s, stdev={baseline_stdev:.3f}s")

    # Smuggling probe: send empty body with ambiguous headers using POST (to force header processing)
    try:
        start = time.monotonic()
        r = session.post(
            endpoint,
            data="",
            headers=_SMUGGLING_HEADERS,
            timeout=config.timeout,
        )
        probe_time = time.monotonic() - start
        config.record_request(r.status_code)
        log_debug(f"Smuggling probe response: status={r.status_code}, time={probe_time:.3f}s")
    except requests.Timeout:
        probe_time = config.timeout
        config.record_request(503)
        log_warning("Smuggling probe timed out – possible server stall.")
        r = None
    except requests.RequestException as e:
        config.record_request(0)
        log_debug(f"Smuggling probe failed: {e}")
        probe_time = None
        r = None

    # Determine timing anomaly via Z‑score
    time_anomaly = False
    if probe_time is not None:
        time_anomaly = is_timing_anomalous(baseline_avg, baseline_stdev, probe_time)

    # Simple response‑header heuristic: if server mirrors ambiguous headers back, that is a strong signal
    header_anomaly = False
    if r and "transfer-encoding" in r.headers:
        header_anomaly = True

    # Confidence logic
    if version_vulnerable and (time_anomaly or header_anomaly):
        detail = (
            f"CONFIRMED: Next.js {version_detected} + ambiguous Transfer‑Encoding/Content‑Length request "
            f"triggered {'header anomaly' if header_anomaly else 'timing anomaly'} (probe {probe_time:.0f}s, baseline avg {baseline_avg:.0f}s)."
        )
        confidence = 0.80
    elif time_anomaly or header_anomaly:
        detail = (
            f"Observed {'header' if header_anomaly else 'timing'} anomaly on ambiguous request. Version unconfirmed – vulnerable if within range.")
        confidence = 0.55
    elif version_vulnerable:
        detail = f"Version {version_detected} matches vulnerable range but no anomaly detected on smuggling probe."
        confidence = 0.35
    else:
        result.status = "SAFE"
        return result

    evidence = {
        "detected_version": version_detected or "unknown",
        "baseline_avg_s": f"{baseline_avg:.3f}",
        "baseline_stdev_s": f"{baseline_stdev:.3f}",
        "probe_time_s": f"{probe_time:.3f}" if probe_time is not None else "timeout",
        "probe_status_code": r.status_code if r else None,
        "header_anomaly": header_anomaly,
        "remediation": "Upgrade Next.js to a version where the request smuggling bug is patched (see advisory).",
    }
    log_warning(detail)
    print_finding(CVE_ID, detail, evidence)
    result.add_finding(Finding(
        cve=CVE_ID,
        severity=CVE_INFO["severity"],
        title="HTTP Request Smuggling",
        status=ScanStatus.VULNERABLE,
        detail=detail,
        evidence=evidence,
        confidence=confidence,
    ))
    return result
