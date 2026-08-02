#!/usr/bin/env python3
"""
NextSploit — CVE-2026-44578: WebSocket Upgrade SSRF (Self-Hosted, 16.x Only)

Root Cause:
  Self-hosted Next.js 16.x applications expose WebSocket upgrade routes that
  reflect the Host header in outbound connections, enabling SSRF to internal
  services. This feature does not exist in Next.js 15.x stable.

Detection Strategy:
  1. Version-based check (16.x only — NOT_APPLICABLE for 15.x and below).
  2. Probe WebSocket upgrade endpoint with manipulated Host header.
  3. Observe if response reflects the injected host.

Affected Versions:
  >= 16.0.0, < 16.2.5  (16.x ONLY — feature not in 15.x)
Fixed In       : 16.2.5
Severity       : High
"""

import requests

from core.config import ScanConfig, CVE_DATABASE, check_vuln_status
from core.reporter import ModuleResult, Finding
from core.output import log_info, log_success, log_warning, log_debug, print_finding

CVE_ID   = "CVE-2026-44578"
CVE_INFO = CVE_DATABASE[CVE_ID]

_WS_PROBE_PATHS = [
    "/_next/webpack-hmr",
    "/api/ws",
    "/ws",
    "/_next/stream",
]
_PROBE_HOST = "nextsploit-ws-ssrf.internal"


def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(
        cve=CVE_ID,
        title=CVE_INFO["title"],
        severity=CVE_INFO["severity"],
        status="NOT VULNERABLE",
    )

    log_info(f"Starting {CVE_ID} scan — WebSocket Upgrade SSRF (16.x only)...")

    # Version check — 16.x ONLY
    best_ver = config.version_state.best()
    version_detected = best_ver.value if best_ver else None

    if version_detected:
        # Explicitly skip for 15.x and below
        try:
            major = int(version_detected.split(".")[0])
            if major < 16:
                result.status = "NOT_APPLICABLE"
                log_info(f"[{CVE_ID}] Next.js {version_detected} is 15.x — WebSocket routes not present. Skipping.")
                return result
        except (ValueError, IndexError):
            pass  # version parse failed — proceed with probe

        vuln_status = check_vuln_status(version_detected, CVE_ID)
        if vuln_status == "PATCHED":
            log_success(f"Version {version_detected} is patched for {CVE_ID}.")
            return result
        if vuln_status == "VULNERABLE":
            log_warning(f"Version {version_detected} is in the vulnerable range (16.x).")

    if not version_detected:
        log_debug("Version unknown — probing for WebSocket endpoints (confidence will be low).")

    session = config.create_session()
    target  = config.target.rstrip("/")

    # Probe WebSocket upgrade paths
    reflected = False
    probe_evidence = {}

    for path in _WS_PROBE_PATHS:
        url = f"{target}{path}"
        try:
            r = session.get(
                url,
                headers={
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Host": _PROBE_HOST,
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                },
                timeout=config.timeout,
                allow_redirects=False,
            )
            log_debug(f"[{r.status_code}] {url}")
            body = r.text[:300]
            location = r.headers.get("Location", "")
            if _PROBE_HOST in body or _PROBE_HOST in location:
                reflected = True
                probe_evidence = {
                    "probe_url": url,
                    "status_code": r.status_code,
                    "reflected_host": _PROBE_HOST,
                    "location": location,
                    "body_snippet": body,
                }
                break
        except requests.RequestException as e:
            log_debug(f"Probe error {url}: {e}")

    if version_detected:
        version_vulnerable = check_vuln_status(version_detected, CVE_ID) == "VULNERABLE"
    else:
        version_vulnerable = False

    if reflected and version_vulnerable:
        detail = (
            f"CONFIRMED: Next.js {version_detected} (16.x vulnerable range) + Host header "
            "reflected in WebSocket upgrade response — SSRF via WebSocket route confirmed."
        )
        confidence = 0.90
    elif reflected:
        detail = (
            "Host header reflected in WebSocket upgrade response. "
            "Version unconfirmed — vulnerable if Next.js >= 16.0.0, < 16.2.5."
        )
        confidence = 0.55
    elif version_vulnerable:
        detail = (
            f"Next.js {version_detected} is in the 16.x vulnerable range. "
            "No Host-header reflection found in WebSocket probe paths."
        )
        confidence = 0.30
    else:
        log_success(f"No {CVE_ID} indicators detected.")
        return result

    probe_evidence["detected_version"] = version_detected or "unknown"
    probe_evidence["remediation"] = "Upgrade to Next.js 16.2.5+."

    log_warning(detail)
    print_finding(CVE_ID, detail, probe_evidence)
    result.add_finding(Finding(
        cve=CVE_ID,
        severity=CVE_INFO["severity"],
        title="WebSocket Upgrade SSRF (Self-Hosted, 16.x Only)",
        status="VULNERABLE",
        detail=detail,
        evidence=probe_evidence,
        confidence=confidence,
    ))
    return result
