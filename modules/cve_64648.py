#!/usr/bin/env python3
"""
NextSploit — CVE-2026-64648: Cache Confusion via fetch() Response Body Mismatch

PASSIVE DEFAULT: Version-based check + INCONCLUSIVE notice (requires --confirm-active).
ACTIVE (--confirm-active): Send two requests with different bodies to same URL,
compare cached responses. WARNING: may pollute shared cache/CDN visible to other users.

Affected: >= 13.0.0, < 15.5.21 | >= 16.0.0, < 16.2.11
"""

import requests
from core.config import ScanConfig
from core.cve_database import CVE_DATABASE, check_vuln_status
from core.reporter import ModuleResult, Finding, ScanStatus
from core.output import log_info, log_success, log_warning, log_debug, print_finding

CVE_ID   = "CVE-2026-64648"
CVE_INFO = CVE_DATABASE[CVE_ID]


def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(cve=CVE_ID, title=CVE_INFO["title"],
                          severity=CVE_INFO["severity"], status=ScanStatus.SAFE)

    session = config.create_session()
    target  = config.target.rstrip("/")
    log_info(f"Starting {CVE_ID} — fetch() cache confusion check...")

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

    if not config.confirm_active:
        # Passive mode: version-only + INCONCLUSIVE
        if version_vulnerable:
            detail = (
                f"Version {version_detected} is in the vulnerable range for {CVE_ID}. "
                "Active confirmation requires --confirm-active (WARNING: may pollute shared cache)."
            )
            result.status=ScanStatus.INCONCLUSIVE
            result.add_finding(Finding(
                cve=CVE_ID, severity=CVE_INFO["severity"],
                title="Cache Confusion (fetch body mismatch) — Unconfirmed",
                status=ScanStatus.INCONCLUSIVE,
                detail=detail,
                evidence={
                    "detected_version": version_detected or "unknown",
                    "note": "Run with --confirm-active for differential cache test.",
                    "warning": "Active test may pollute shared CDN cache visible to other users.",
                },
                confidence=0.35,
            ))
            log_warning(detail)
        else:
            log_success(f"No {CVE_ID} indicators detected (passive mode).")
        return result

    # Active mode
    log_warning(
        "[!] CVE-2026-64648: Active mode — this test sends two different request bodies "
        "to the same URL and may pollute shared cache/CDN state visible to other users of the target."
    )

    probe_url = f"{target}/api/data"
    body_a = b"nextsploit-cache-probe-A"
    body_b = b"nextsploit-cache-probe-B"
    confused = False
    active_evidence = {}

    try:
        r_a = session.post(probe_url, data=body_a, headers={"Content-Type": "text/plain"},
                           timeout=config.timeout)
        r_b = session.post(probe_url, data=body_b, headers={"Content-Type": "text/plain"},
                           timeout=config.timeout)
        # Confusion indicator: same response body despite different request bodies
        if r_a.status_code == 200 and r_b.status_code == 200 and r_a.text == r_b.text:
            cache_a = r_a.headers.get("x-nextjs-cache", r_a.headers.get("cf-cache-status", ""))
            cache_b = r_b.headers.get("x-nextjs-cache", r_b.headers.get("cf-cache-status", ""))
            if "HIT" in cache_b.upper():
                confused = True
                active_evidence = {
                    "probe_url": probe_url,
                    "body_a": body_a.decode(),
                    "body_b": body_b.decode(),
                    "response_a_status": r_a.status_code,
                    "response_b_status": r_b.status_code,
                    "response_b_cache": cache_b,
                    "detection": "Response B cache-hit returned same body as Response A — cache confusion.",
                }
        log_debug(f"Active test: A={r_a.status_code} B={r_b.status_code} same_body={r_a.text == r_b.text}")
    except requests.RequestException as e:
        log_debug(f"Active probe error: {e}")

    if confused and version_vulnerable:
        detail = f"CONFIRMED: {version_detected} + cache confusion confirmed via differential body test."
        confidence = 0.88
    elif confused:
        detail = "Cache confusion confirmed (different bodies, same cached response). Version unconfirmed."
        confidence = 0.60
    elif version_vulnerable:
        detail = f"{version_detected} in vulnerable range. Active differential test did not confirm confusion."
        confidence = 0.35
    else:
        log_success(f"No {CVE_ID} indicators detected (active mode).")
        return result

    active_evidence["detected_version"] = version_detected or "unknown"
    active_evidence["remediation"] = "Upgrade to 15.5.21+ or 16.2.11+."
    log_warning(detail)
    print_finding(CVE_ID, detail, active_evidence)
    result.add_finding(Finding(cve=CVE_ID, severity=CVE_INFO["severity"],
        title="Cache Confusion — fetch() Response Body Mismatch",
        status=ScanStatus.VULNERABLE, detail=detail, evidence=active_evidence, confidence=confidence))
    return result
