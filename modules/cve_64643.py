#!/usr/bin/env python3
"""
NextSploit — CVE-2026-64643: Server Action / use cache Endpoint ID Enumerable

Root Cause:
  Server Action and 'use cache' endpoint IDs are exposed in error responses
  and can be enumerated without authentication, providing a reconnaissance vector.

Detection Strategy:
  PASSIVE only — Read error responses from SA endpoint for exposed IDs.
  No flag needed, no risk of side effects.

Affected Versions:
  >= 15.0.0, < 15.5.21 | >= 16.0.0, < 16.2.11
"""

import re
import requests

from core.config import ScanConfig
from core.cve_database import CVE_DATABASE, check_vuln_status
from core.reporter import ModuleResult, Finding, ScanStatus
from core.output import log_info, log_success, log_warning, log_debug, print_finding

CVE_ID   = "CVE-2026-64643"
CVE_INFO = CVE_DATABASE[CVE_ID]

_ACTION_ID_IN_ERROR_RE = re.compile(r'["\']([0-9a-f]{8,40})["\']')


def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(cve=CVE_ID, title=CVE_INFO["title"],
                          severity=CVE_INFO["severity"], status=ScanStatus.SAFE)

    if not config.has_active_server_actions():
        result.status=ScanStatus.NOT_APPLICABLE
        log_info(f"[{CVE_ID}] No Server Action IDs discovered — skipping.")
        return result

    session = config.create_session()
    target  = config.target.rstrip("/")

    log_info(f"Starting {CVE_ID} — SA endpoint ID enumeration check...")

    best_ver = config.version_state.best()
    version_detected = best_ver.value if best_ver else None
    version_vulnerable = False
    if version_detected:
        vs = check_vuln_status(version_detected, CVE_ID)
        if vs == "PATCHED":
            log_success(f"{version_detected} is patched.")
            return result
        if vs == "VULNERABLE":
            version_vulnerable = True

    # Probe: send invalid action to SA endpoint and look for ID leak in error body
    found_ids = set()
    try:
        r = session.post(target + "/", data="probe",
                         headers={"Next-Action": "00000000invalid", "Content-Type": "text/plain"},
                         timeout=config.timeout)
        log_debug(f"SA error probe: {r.status_code}")
        matches = _ACTION_ID_IN_ERROR_RE.findall(r.text)
        # Filter out known false positives
        found_ids = {m for m in matches if m not in {"00000000", "ffffffff", "deadbeef"}
                     and len(m) >= 8}
        if found_ids:
            log_warning(f"Found {len(found_ids)} potential Action IDs in error response.")
    except requests.RequestException as e:
        log_debug(f"Probe error: {e}")

    if found_ids and version_vulnerable:
        confidence, status_label = 0.85, "VULNERABLE"
        detail = (f"CONFIRMED: {len(found_ids)} Server Action IDs leaked in error response "
                  f"on Next.js {version_detected}.")
    elif found_ids:
        confidence, status_label = 0.55, "VULNERABLE"
        detail = (f"{len(found_ids)} Action IDs leaked in error response. "
                  "Version unconfirmed — vulnerable if < 15.5.21 or < 16.2.11.")
    elif version_vulnerable:
        confidence, status_label = 0.30, "VULNERABLE"
        detail = (f"Version {version_detected} in vulnerable range but no ID leak found in probe.")
    else:
        log_success(f"No {CVE_ID} indicators detected.")
        return result

    evidence = {
        "leaked_action_ids": list(found_ids)[:10],
        "detected_version": version_detected or "unknown",
        "remediation": "Upgrade to Next.js 15.5.21+ or 16.2.11+.",
    }
    log_warning(detail)
    print_finding(CVE_ID, detail, evidence)
    result.add_finding(Finding(cve=CVE_ID, severity=CVE_INFO["severity"],
        title="Server Action Endpoint ID Enumerable Without Auth",
        status=status_label, detail=detail, evidence=evidence, confidence=confidence))
    return result
