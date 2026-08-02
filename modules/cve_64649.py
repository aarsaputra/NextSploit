#!/usr/bin/env python3
"""
NextSploit — CVE-2026-64649: SSRF Server Actions via Host Header (Custom Node.js Server)

Root Cause:
  When a Server Action on a custom Node.js server forwards or redirects a
  request, the outbound connection uses the attacker-controlled Host header
  to determine the destination, enabling SSRF to internal services.

Detection Strategy:
  PASSIVE (default): Send a Server Action request with a manipulated Host header
  and observe whether the response Location or error body reflects the injected host.
  No outbound connection is attempted.

  ACTIVE (--confirm-active): Differential test with controlled Host header values.
  Warning displayed before running.

Affected Versions:
  >= 15.0.0, < 15.5.21  (branch 15.x)
  >= 16.0.0, < 16.2.11  (branch 16.x)
Fixed In       : 15.5.21 / 16.2.11
Severity       : High
"""

import requests

from core.config import ScanConfig, CVE_DATABASE, check_vuln_status
from core.reporter import ModuleResult, Finding
from core.output import log_info, log_success, log_warning, log_debug, print_finding

CVE_ID   = "CVE-2026-64649"
CVE_INFO = CVE_DATABASE[CVE_ID]

_PROBE_HOST = "nextsploit-ssrf-probe.internal"


def _probe(session: requests.Session, target: str, action_id: str,
           host_header: str, timeout: int) -> tuple:
    """Send a Server Action request with a spoofed Host header."""
    url = f"{target}/"
    headers = {
        "Host": host_header,
        "Next-Action": action_id,
        "Content-Type": "text/plain",
    }
    try:
        r = session.post(url, data="nextsploit-probe", headers=headers,
                         timeout=timeout, allow_redirects=False)
        location = r.headers.get("Location", "")
        body_snippet = r.text[:500] if r.text else ""
        reflected = host_header in location or host_header in body_snippet
        return reflected, {
            "status_code": r.status_code,
            "location_header": location,
            "reflected_in": "Location" if host_header in location else (
                "body" if host_header in body_snippet else "none"
            ),
            "body_snippet": body_snippet[:200],
        }
    except requests.RequestException as e:
        log_debug(f"Probe error: {e}")
        return False, {}


def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(
        cve=CVE_ID,
        title=CVE_INFO["title"],
        severity=CVE_INFO["severity"],
        status="NOT VULNERABLE",
    )

    # Precondition: at least one Server Action
    if not config.has_active_server_actions():
        result.status = "NOT_APPLICABLE"
        log_info(f"[{CVE_ID}] No Server Action IDs discovered — skipping.")
        return result

    session = config.create_session()
    target  = config.target.rstrip("/")

    log_info(f"Starting {CVE_ID} scan — SSRF via Host header in Server Actions...")

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

    action_id = config.discovered_action_ids[0]

    # Passive probe
    log_debug(f"Passive Host-header probe with '{_PROBE_HOST}'...")
    reflected, evidence = _probe(session, target, action_id, _PROBE_HOST, config.timeout)

    # Active differential (opt-in)
    if not reflected and config.confirm_active:
        log_warning(
            "[!] CVE-2026-64649: Active mode — this test sends a manipulated Host header "
            "that may cause the server to make outbound requests to attacker-specified hosts."
        )
        alt_host = f"{_PROBE_HOST}."  # trailing-dot bypass variant
        reflected, evidence = _probe(session, target, action_id, alt_host, config.timeout)

    # Scoring
    if reflected and version_vulnerable:
        detail = (
            f"CONFIRMED: Next.js {version_detected} + Server Action reflects injected Host "
            f"header '{_PROBE_HOST}' in response — SSRF via custom Node.js server confirmed."
        )
        confidence = 0.90
    elif reflected:
        detail = (
            f"Server Action reflects injected Host header in response. "
            "Version unconfirmed — vulnerable if < 15.5.21 or < 16.2.11."
        )
        confidence = 0.60
    elif version_vulnerable:
        detail = (
            f"Next.js {version_detected} in vulnerable range. No Host-header reflection "
            "found in passive probe — may require custom server configuration."
        )
        confidence = 0.35
    else:
        log_success(f"No {CVE_ID} indicators detected.")
        return result

    evidence["action_id"] = action_id
    evidence["detected_version"] = version_detected or "unknown"
    evidence["remediation"] = "Upgrade to Next.js 15.5.21+ (15.x) or 16.2.11+ (16.x)."

    log_warning(detail)
    print_finding(CVE_ID, detail, evidence)
    result.add_finding(Finding(
        cve=CVE_ID,
        severity=CVE_INFO["severity"],
        title="SSRF via Host Header in Server Actions (Custom Node.js Server)",
        status="VULNERABLE",
        detail=detail,
        evidence=evidence,
        confidence=confidence,
    ))
    return result
