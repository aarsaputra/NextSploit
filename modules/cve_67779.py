#!/usr/bin/env python3
"""
NextSploit — CVE-2025-67779: DoS via Incomplete Fix (Infinite Promise Recursion)

Background:
  CVE-2025-55184 was patched with an INCOMPLETE fix. This CVE covers the
  remaining attack surface in react-server-dom-* packages. When a specially
  crafted RSC payload containing circular/recursive Promise references is
  sent to an App Router endpoint, the deserializer enters an infinite
  recursion loop, hanging the Node.js process (DoS).

Affected:
  react-server-dom-webpack  19.0.2, 19.1.3, 19.2.2
  react-server-dom-parcel   19.0.2, 19.1.3, 19.2.2
  react-server-dom-turbopack 19.0.2, 19.1.3, 19.2.2
  (and Next.js versions bundling those React packages)

Fixed In:
  React    19.0.3 / 19.1.4 / 19.2.3
  Next.js  15.3.0+ (bundling patched React)

CVSS: 7.5 (High)

Detection Strategy:
  1. Version-based check (primary — 0% false positive rate).
  2. Non-destructive timing probe: POST a minimal recursive-promise RSC
     payload to App Router endpoints and measure response latency.
     A vulnerable server will exhibit abnormal processing time even for
     a tiny payload before the watchdog kills the request.
     Cap: safe payload size, no actual OOM induction.
"""

import time
import requests

from core.config import ScanConfig, CVE_DATABASE, check_vuln_status
from core.reporter import ModuleResult, Finding
from core.output import (
    log_info, log_success, log_warning, log_critical, log_debug,
    log_trace, print_module_header, print_finding, create_progress,
)

CVE_ID   = "CVE-2025-67779"
CVE_INFO = CVE_DATABASE[CVE_ID]

# ── Timing thresholds ────────────────────────────────────────────────────────
_TIMING_SUSPICIOUS  = 4.0   # seconds — slower than typical RSC response
_TIMING_HIGH_CONF   = 8.0   # seconds — strong indicator of infinite loop

# ── Non-destructive RSC payloads ─────────────────────────────────────────────
# These payloads mimic the structure that triggers recursive Promise resolution
# but are intentionally minimal to avoid actually hanging the server.
# The vulnerable parser takes measurably longer even on tiny recursive chains.
_PROBE_PAYLOADS = [
    # Minimal circular-reference RSC flight data
    b'0:{"then":{"then":{"then":{"then":null}}}}\n',
    # Null-terminated promise chain
    b'1:{"$$typeof":"$","key":null,"ref":null,"props":{"then":{"then":null}}}\n',
    # Empty module reference that forces promise resolution
    b'2:I["",[]]\n3:{"children":"$L2"}\n0:["$","div",null,{"children":"$L3"}]\n',
]

# ── Candidate endpoints for RSC probe ────────────────────────────────────────
_RSC_ENDPOINTS = [
    "/",
    "/api/",
]

_RSC_HEADERS = {
    "Accept"      : "text/x-component",
    "RSC"         : "1",
    "Content-Type": "text/x-component",
}


def _find_rsc_endpoint(session: requests.Session, target: str, timeout: int) -> str | None:
    """
    Locate a live RSC / App Router endpoint.
    Returns the first URL that responds to RSC content-type, or None.
    """
    for path in _RSC_ENDPOINTS:
        url = f"{target}{path}"
        try:
            r = session.get(url, headers={"RSC": "1", "Accept": "text/x-component"},
                            timeout=timeout, allow_redirects=False)
            ct = r.headers.get("content-type", "")
            # App Router RSC responses carry text/x-component
            if "text/x-component" in ct or r.status_code in (200, 400):
                log_debug(f"RSC endpoint found: {url} → HTTP {r.status_code} ({ct[:40]})")
                return url
        except requests.RequestException:
            continue
    return None


def scan(config: ScanConfig) -> ModuleResult:
    """
    Scan for CVE-2025-67779 (DoS — Incomplete Fix follow-up).

    Phase 1: Version-based detection (highest confidence).
    Phase 2: Non-destructive timing probe on RSC endpoints.
    """
    result = ModuleResult(
        cve=CVE_ID,
        title=CVE_INFO["title"],
        severity=CVE_INFO["severity"],
        status="NOT VULNERABLE",
    )
    print_module_header(CVE_ID, CVE_INFO["title"], CVE_INFO["severity"])
    log_info(
        "Note: This CVE is the COMPLETE fix for the incomplete CVE-2025-55184 patch. "
        "If 55184 was flagged, this module confirms whether the follow-up fix is applied."
    )

    session = config.create_session()
    target  = config.target.rstrip("/")

    # ── Phase 1: Version-based check ─────────────────────────────────────────
    log_info("[Phase 1] Version-based vulnerability check...")
    version_detected = getattr(config, "discovered_version", None)

    if version_detected:
        log_debug(f"Detected Next.js version: {version_detected}")
        vuln_status = check_vuln_status(version_detected, CVE_ID)

        if vuln_status == "PATCHED":
            log_success(
                f"Version {version_detected} is patched for {CVE_ID} (fix: >= 15.3.0)."
            )
            return result

        if vuln_status == "VULNERABLE":
            detail = (
                f"Next.js {version_detected} bundles a React version that is in the "
                f"vulnerable range for {CVE_ID} (affected: React 19.0.2/19.1.3/19.2.2, "
                f"fix: React 19.0.3+ / Next.js 15.3.0+). "
                f"Infinite promise recursion DoS is possible via crafted RSC payloads."
            )
            log_critical(detail)
            evidence = {
                "detected_version"     : version_detected,
                "vulnerability_status" : "VULNERABLE (version-based)",
                "related_cve"          : "CVE-2025-55184 (incomplete predecessor patch)",
                "affected_packages"    : "react-server-dom-webpack / parcel / turbopack < 19.0.3",
                "attack_vector"        : "POST crafted RSC flight payload to any App Router endpoint",
                "remediation"          : (
                    "Upgrade Next.js to 15.3.0+ (bundles React 19.0.3+). "
                    "Alternatively, upgrade react-server-dom-* directly to 19.0.3/19.1.4/19.2.3."
                ),
            }
            print_finding(CVE_ID, detail, evidence)
            result.add_finding(Finding(
                cve=CVE_ID,
                severity=CVE_INFO["severity"],
                title="Vulnerable Version Detected — Incomplete DoS Fix",
                status="VULNERABLE",
                detail=detail,
                evidence=evidence,
                confidence=0.92,
            ))
            return result

    # ── Phase 2: Non-destructive timing probe ─────────────────────────────────
    log_info("[Phase 2] Non-destructive RSC timing probe (version unknown)...")
    log_debug("Locating RSC endpoint...")

    endpoint = _find_rsc_endpoint(session, target, config.timeout)
    if endpoint is None:
        log_debug("No RSC/App Router endpoint found — target may not use App Router.")
        log_success(f"No {CVE_ID} indicators detected.")
        return result

    log_debug(f"Using endpoint for timing probe: {endpoint}")

    # Establish a baseline GET response time for comparison
    try:
        t0 = time.time()
        session.get(endpoint, timeout=config.timeout, allow_redirects=False)
        baseline_time = time.time() - t0
        log_debug(f"Baseline GET time: {baseline_time:.2f}s")
    except requests.RequestException:
        baseline_time = 1.0

    with create_progress() as progress:
        task = progress.add_task("RSC Promise Timing Probe", total=len(_PROBE_PAYLOADS))

        for i, payload in enumerate(_PROBE_PAYLOADS, 1):
            progress.update(task, advance=1)
            try:
                t0 = time.time()
                r  = session.post(
                    endpoint,
                    headers=_RSC_HEADERS,
                    data=payload,
                    timeout=max(config.timeout, 15),
                )
                elapsed = time.time() - t0
                ratio   = elapsed / baseline_time if baseline_time > 0 else 0

                log_trace(
                    f"Probe #{i}: HTTP {r.status_code} | {elapsed:.2f}s "
                    f"| {ratio:.1f}x baseline | {len(payload)}B payload"
                )

                if elapsed >= _TIMING_HIGH_CONF or ratio > 6:
                    confidence = 0.80
                    sev        = "HIGH"
                    title      = "High-Confidence RSC Infinite-Loop Indicator"
                    log_critical(
                        f"Probe #{i}: {elapsed:.2f}s response ({ratio:.1f}x baseline) "
                        f"— strong indicator of promise recursion loop."
                    )
                elif elapsed >= _TIMING_SUSPICIOUS or ratio > 4:
                    confidence = 0.60
                    sev        = "MEDIUM"
                    title      = "Suspicious RSC Response Latency"
                    log_warning(
                        f"Probe #{i}: {elapsed:.2f}s response ({ratio:.1f}x baseline) "
                        f"— may indicate slow promise resolution."
                    )
                else:
                    log_trace(f"Probe #{i}: within normal range ({elapsed:.2f}s).")
                    continue

                detail = (
                    f"RSC endpoint {endpoint} took {elapsed:.2f}s to respond to "
                    f"a {len(payload)}-byte recursive-promise probe payload "
                    f"({ratio:.1f}x baseline). Likely vulnerable to {CVE_ID} DoS."
                )
                evidence = {
                    "endpoint"          : endpoint,
                    "probe_index"       : i,
                    "payload_size_bytes": len(payload),
                    "response_time_s"   : round(elapsed, 2),
                    "baseline_time_s"   : round(baseline_time, 2),
                    "slowdown_ratio"    : round(ratio, 1),
                    "response_status"   : r.status_code,
                    "related_cve"       : "CVE-2025-55184 (incomplete predecessor patch)",
                    "note"              : "Timing-based detection — confirm with version check.",
                    "remediation"       : "Upgrade Next.js to 15.3.0+ (React 19.0.3+).",
                }
                print_finding(CVE_ID, detail, evidence)
                result.add_finding(Finding(
                    cve=CVE_ID,
                    severity=sev,
                    title=title,
                    status="VULNERABLE",
                    detail=detail,
                    evidence=evidence,
                    confidence=confidence,
                ))

            except requests.exceptions.Timeout:
                detail = (
                    f"RSC endpoint {endpoint} timed out (>{config.timeout}s) during "
                    f"recursive-promise probe #{i} — potential infinite loop / DoS indicator."
                )
                log_critical(detail)
                evidence = {
                    "endpoint"    : endpoint,
                    "probe_index" : i,
                    "note"        : "Server timeout may indicate promise recursion DoS.",
                    "related_cve" : "CVE-2025-55184 (incomplete predecessor patch)",
                    "remediation" : "Upgrade Next.js to 15.3.0+ (React 19.0.3+).",
                }
                print_finding(CVE_ID, detail, evidence)
                result.add_finding(Finding(
                    cve=CVE_ID,
                    severity="HIGH",
                    title="RSC Endpoint Timeout — Potential Infinite Loop DoS",
                    status="VULNERABLE",
                    detail=detail,
                    evidence=evidence,
                    confidence=0.70,
                ))

            except requests.RequestException as e:
                log_trace(f"Probe #{i} network error: {e}")

    if result.finding_count == 0:
        log_success(f"No {CVE_ID} indicators detected on target.")

    return result
