#!/usr/bin/env python3
"""
NextSploit — CVE-2026-64646: Unbounded SA Payload Edge Runtime Memory Exhaustion

Version-based check + safe probe with small payload to confirm Edge SA endpoint
exists. Does NOT send a large payload.

Affected: >= 15.0.0, < 15.5.21 | >= 16.0.0, < 16.2.11
"""

import requests
from core.config import ScanConfig, CVE_DATABASE, check_vuln_status
from core.reporter import ModuleResult, Finding
from core.output import log_info, log_success, log_warning, log_debug, print_finding

CVE_ID   = "CVE-2026-64646"
CVE_INFO = CVE_DATABASE[CVE_ID]


def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(cve=CVE_ID, title=CVE_INFO["title"],
                          severity=CVE_INFO["severity"], status="NOT VULNERABLE")

    if not config.has_active_server_actions():
        result.status = "NOT_APPLICABLE"
        log_info(f"[{CVE_ID}] No Server Action IDs — skipping.")
        return result
    if not config.has_app_router():
        result.status = "NOT_APPLICABLE"
        log_info(f"[{CVE_ID}] Pages Router detected — skipping.")
        return result

    session = config.create_session()
    target  = config.target.rstrip("/")
    log_info(f"Starting {CVE_ID} — Edge runtime SA memory exhaustion check...")

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
            log_warning(f"{version_detected} is in the vulnerable range.")

    action_id = config.discovered_action_ids[0]
    edge_active = False
    try:
        r = session.post(
            target + "/",
            data="x" * 128,  # safe 128-byte probe, nowhere near OOM threshold
            headers={"Next-Action": action_id, "Content-Type": "text/plain"},
            timeout=config.timeout,
        )
        edge_header = r.headers.get("x-edge-runtime", "") or r.headers.get("x-vercel-runtime", "")
        if "edge" in edge_header.lower():
            edge_active = True
            log_warning("Edge runtime response header detected.")
        log_debug(f"SA Edge probe: [{r.status_code}] edge_header='{edge_header}'")
    except requests.RequestException as e:
        log_debug(f"Probe error: {e}")

    if edge_active and version_vulnerable:
        detail = f"CONFIRMED: {version_detected} + Edge runtime SA endpoint active — unbounded payload possible."
        confidence = 0.82
    elif edge_active:
        detail = "Edge runtime SA endpoint detected. Version unconfirmed — vulnerable if < 15.5.21 or < 16.2.11."
        confidence = 0.50
    elif version_vulnerable:
        detail = f"{version_detected} in vulnerable range. No Edge runtime header detected in probe."
        confidence = 0.30
    else:
        log_success(f"No {CVE_ID} indicators detected.")
        return result

    evidence = {"detected_version": version_detected or "unknown",
                "edge_runtime_active": edge_active,
                "remediation": "Upgrade to 15.5.21+ or 16.2.11+."}
    log_warning(detail)
    print_finding(CVE_ID, detail, evidence)
    result.add_finding(Finding(cve=CVE_ID, severity=CVE_INFO["severity"],
        title="Unbounded SA Payload Edge Runtime Memory Exhaustion",
        status="VULNERABLE", detail=detail, evidence=evidence, confidence=confidence))
    return result
