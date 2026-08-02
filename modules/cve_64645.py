#!/usr/bin/env python3
"""
NextSploit — CVE-2026-64645: SSRF via rewrites()/redirects() Hostname Injection

Root Cause:
  A rewrites() or redirects() rule that builds its external destination
  hostname from request-controlled input (path segment, query param, etc.)
  can be pointed at an arbitrary hostname, enabling SSRF to internal services
  and cloud metadata endpoints (e.g. 169.254.169.254).

Detection Strategy:
  PASSIVE (default): Probe candidate redirect endpoints and analyze the
  Location header for signs that the host portion is reflected from request
  input (trailing-dot bypass pattern, reflected path segments in FQDN, etc.).
  No connection is made to any external host.

  ACTIVE (--confirm-active): Perform differential test using an
  attacker-controlled host suffix. A warning is displayed before the test runs.

Affected Versions:
  >= 12.0.0, < 15.5.21  (branch 15.x)
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

CVE_ID   = "CVE-2026-64645"
CVE_INFO = CVE_DATABASE[CVE_ID]

# Paths commonly configured as rewrite/redirect destinations built from input
_PROBE_PATHS = [
    "/api/proxy/{host}",
    "/redirect?to={host}",
    "/r/{host}",
    "/_next/proxy/{host}",
    "/goto/{host}",
    "/link/{host}",
]

# Patterns that suggest a reflected host in a Location header
_REFLECTED_HOST_RE = re.compile(
    r"https?://([a-zA-Z0-9.-]+\.nextsploit-probe)",
    re.IGNORECASE,
)
_TRAILING_DOT_RE = re.compile(
    r"Location:\s*https?://[^/\s]+\.[^/\s]+\.",  # trailing dot before path
    re.IGNORECASE,
)


def _passive_probe(session: requests.Session, target: str, timeout: int) -> tuple:
    """
    Probe redirect/rewrite endpoints passively.
    Returns (reflected: bool, evidence: dict).
    """
    probe_host = "nextsploit-probe.internal"
    for path_tpl in _PROBE_PATHS:
        path = path_tpl.format(host=probe_host)
        url = f"{target}{path}"
        try:
            r = session.get(url, timeout=timeout, allow_redirects=False)
            location = r.headers.get("Location", "")
            if _REFLECTED_HOST_RE.search(location):
                return True, {
                    "probe_url": url,
                    "status_code": r.status_code,
                    "location_header": location,
                    "detection": "reflected probe host in Location header",
                }
            if _TRAILING_DOT_RE.search(f"Location: {location}"):
                return True, {
                    "probe_url": url,
                    "status_code": r.status_code,
                    "location_header": location,
                    "detection": "trailing-dot pattern in Location header (SSRF bypass indicator)",
                }
            log_debug(f"[{r.status_code}] {url} — Location: {location or '(none)'}")
        except requests.RequestException as e:
            log_debug(f"Network error probing {url}: {e}")
    return False, {}


def _active_probe(session: requests.Session, target: str, timeout: int) -> tuple:
    """
    Active differential test — only runs when --confirm-active is set.
    Tests if a controlled host suffix appears in redirect Location.
    NOTE: This probe does NOT make outbound connections to external hosts;
    it only checks if the server would redirect there.
    """
    probe_host = "nextsploit-ssrf-confirm.internal."   # trailing dot bypass
    for path_tpl in _PROBE_PATHS:
        path = path_tpl.format(host=probe_host)
        url = f"{target}{path}"
        try:
            r = session.get(url, timeout=timeout, allow_redirects=False)
            location = r.headers.get("Location", "")
            if probe_host.rstrip(".") in location or "nextsploit" in location.lower():
                return True, {
                    "probe_url": url,
                    "status_code": r.status_code,
                    "location_header": location,
                    "detection": "active differential: controlled host reflected in redirect (SSRF confirmed)",
                }
        except requests.RequestException as e:
            log_debug(f"Active probe error {url}: {e}")
    return False, {}


def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(
        cve=CVE_ID,
        title=CVE_INFO["title"],
        severity=CVE_INFO["severity"],
        status="NOT VULNERABLE",
    )

    session = config.create_session()
    target  = config.target.rstrip("/")

    log_info(f"Starting {CVE_ID} scan — SSRF via rewrites/redirects hostname injection...")

    # ── Version check ────────────────────────────────────────────────────────
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

    # ── Passive probe ─────────────────────────────────────────────────────────
    log_debug("Running passive redirect/rewrite probe...")
    reflected, evidence = _passive_probe(session, target, config.timeout)

    # ── Active probe (opt-in) ─────────────────────────────────────────────────
    if not reflected and config.confirm_active:
        log_warning(
            "[!] CVE-2026-64645: Active mode — this test causes the target to attempt "
            "outbound requests to attacker-specified hosts. Only run on targets you own."
        )
        reflected, evidence = _active_probe(session, target, config.timeout)

    # ── Confidence scoring ────────────────────────────────────────────────────
    if reflected and version_vulnerable:
        detail     = (
            f"CONFIRMED: Next.js {version_detected} is in vulnerable range AND rewrite/redirect "
            "endpoint reflects attacker-controlled host in Location header — SSRF confirmed."
        )
        confidence = 0.92
    elif reflected:
        detail     = (
            "Rewrite/redirect endpoint reflects attacker-controlled host in Location header. "
            "Version unconfirmed — vulnerable if Next.js < 15.5.21 or < 16.2.11."
        )
        confidence = 0.60
    elif version_vulnerable:
        detail     = (
            f"Next.js {version_detected} is in vulnerable range for CVE-2026-64645 "
            "but no active rewrite/redirect reflection found in passive probe. "
            "The vulnerability requires a specific routing configuration — manual review recommended."
        )
        confidence = 0.35
    else:
        log_success(f"No {CVE_ID} indicators detected (passive probe).")
        return result

    evidence["remediation"] = "Upgrade Next.js to 15.5.21+ (15.x) or 16.2.11+ (16.x)."
    evidence["detected_version"] = version_detected or "unknown"

    log_warning(detail)
    print_finding(CVE_ID, detail, evidence)
    result.add_finding(Finding(
        cve=CVE_ID,
        severity=CVE_INFO["severity"],
        title="SSRF via rewrites()/redirects() Hostname Injection",
        status="VULNERABLE",
        detail=detail,
        evidence=evidence,
        confidence=confidence,
    ))
    return result
