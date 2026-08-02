#!/usr/bin/env python3
"""
NextSploit — GHSA-mg66-mrh9-m8jx: DoS via PPR/Cache Components Deadlock

Root Cause:
  When Partial Pre-Rendering (PPR) or cacheComponents is enabled, a POST
  request with the 'Next-Resume: 1' header deadlocks the connection pool.
  Concurrent requests pile up until the process exhausts handles — DoS.

Detection Strategy:
  1. Version-based check (primary).
  2. PPR detection via 'Next-Resume' differential response.
  Only report when version AND/OR PPR conditions are confirmed.

Affected Versions : Next.js < 15.5.16 (with PPR enabled)
Fixed In          : 15.5.16
Severity          : High
"""

import requests
from core.config import ScanConfig
from core.cve_database import CVE_DATABASE, check_vuln_status
from core.reporter import ModuleResult, Finding, ScanStatus
from core.output import log_info, log_success, log_warning, log_debug, print_finding

CVE_ID   = "GHSA-mg66-mrh9-m8jx"
CVE_INFO = CVE_DATABASE[CVE_ID]


def _detect_ppr(session: requests.Session, target: str, timeout: int) -> bool:
    """Detect PPR activation via Next-Resume differential probe."""
    base_headers = {"Content-Type": "application/json", "Accept": "text/x-component"}
    try:
        r_without = session.post(f"{target}/", headers=base_headers,
                                 data="{}", timeout=timeout, allow_redirects=False)
        r_with    = session.post(f"{target}/", headers={**base_headers, "Next-Resume": "1"},
                                 data="{}", timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        return False

    log_debug(f"Next-Resume probe: without={r_without.status_code} with={r_with.status_code}")

    if r_without.status_code != r_with.status_code:
        return True
    sz_without = len(r_without.content)
    sz_with    = len(r_with.content)
    if sz_without > 0 and abs(sz_with - sz_without) / sz_without > 0.1:
        return True
    for resp in (r_without, r_with):
        if "x-nextjs-cache" in resp.headers or "rsc" in resp.headers.get("vary", "").lower():
            return True
    return False


def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(
        cve=CVE_ID,
        title=CVE_INFO["title"],
        severity=CVE_INFO["severity"],
        status=ScanStatus.SAFE,
    )

    # Precondition Checks
    if not config.has_app_router():
        result.status=ScanStatus.NOT_APPLICABLE
        log_info(f"[{CVE_ID}] App router not detected. Skipping.")
        return result

    session = config.create_session()
    target  = config.target.rstrip("/")

    log_info(f"Starting {CVE_ID} scan — PPR/Cache Components Deadlock DoS...")

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

    log_debug("Probing for PPR/cacheComponents via Next-Resume header...")
    ppr_active = _detect_ppr(session, target, config.timeout)
    if ppr_active:
        log_warning("PPR/cacheComponents appears active on the target.")
    else:
        log_debug("PPR not detected — CVE requires PPR to be enabled.")

    if version_vulnerable and ppr_active:
        detail     = (f"CONFIRMED: Next.js {version_detected} (< 15.5.16) + PPR active. "
                      "Connection-pool deadlock DoS possible via 'Next-Resume: 1'.")
        confidence = 0.90
    elif version_vulnerable:
        detail     = (f"Next.js {version_detected} is vulnerable but PPR not detected. "
                      "Exploitable only if PPR is enabled in next.config.")
        confidence = 0.50
    elif ppr_active and not version_detected:
        detail     = "PPR active but version unknown. Vulnerable if version < 15.5.16."
        confidence = 0.55
    else:
        log_success(f"No {CVE_ID} indicators detected.")
        return result

    evidence = {
        "detected_version"   : version_detected or "unknown",
        "ppr_active"         : ppr_active,
        "attack_vector"      : "POST to any route with 'Next-Resume: 1' header.",
        "requirement"        : "experimental.ppr: true or cacheComponents in next.config.",
        "remediation"        : "Upgrade Next.js to 15.5.16 or newer.",
    }
    log_warning(detail)
    print_finding(CVE_ID, detail, evidence)
    result.add_finding(Finding(
        cve=CVE_ID,
        severity=CVE_INFO["severity"],
        title="PPR/Cache Components Deadlock DoS",
        status=ScanStatus.VULNERABLE,
        detail=detail,
        evidence=evidence,
        confidence=confidence,
    ))
    return result

