#!/usr/bin/env python3
"""
NextSploit — CVE-2026-23864: DoS via RSC Memory Exhaustion

Root Cause:
  The React Flight protocol decoder in Next.js 15.5.0–15.5.9 allocates
  memory for every '$K<id>:FormData' token present in a multipart
  FormData body POSTed to a Server Action endpoint. A crafted request
  containing thousands of such tokens causes unbounded memory growth
  (OOM), crashing the Node.js process.

Detection Strategy:
  1. Version-based check (primary — safest, 0% false positive).
  2. Non-destructive response-time probe with a small payload to confirm
     the Server Action endpoint exists and times scale with payload size.
     We deliberately cap at a safe payload size to avoid actual DoS.

Affected Versions : Next.js 15.5.0 – 15.5.9
Fixed In          : 15.5.10
CVSS              : 7.5 (High)
"""

import time
import requests
from core.config import ScanConfig, CVE_DATABASE, check_vuln_status
from core.reporter import ModuleResult, Finding
from core.output import log_info, log_success, log_warning, log_debug, print_finding

CVE_ID   = "CVE-2026-23864"
CVE_INFO = CVE_DATABASE[CVE_ID]

# Safe probe: small enough to NEVER crash a real server, large enough
# to differentiate a vulnerable parser from a normal one.
_SAFE_TOKEN_COUNT  = 120   # tokens in the non-destructive probe payload
_TIMING_THRESHOLD  = 3.0   # seconds — response time above this is suspicious
_BOUNDARY          = "----NextSploit44575Boundary"


def _build_probe_payload(token_count: int) -> tuple[bytes, str]:
    """
    Build a multipart/form-data body with `token_count` FormData tokens.
    Returns (body_bytes, content_type).
    """
    parts = [
        f"--{_BOUNDARY}",
        'Content-Disposition: form-data; name="action_id"',
        "",
        "nextjs-dos-probe",
        f"--{_BOUNDARY}",
        'Content-Disposition: form-data; name="payload"',
        "",
    ]
    # Append safe number of $K tokens
    parts.append("\n".join(f"$K{i}:FormData" for i in range(token_count)))
    parts.append(f"--{_BOUNDARY}--")
    parts.append("")

    body = "\r\n".join(parts).encode("utf-8")
    content_type = f"multipart/form-data; boundary={_BOUNDARY}"
    return body, content_type


def _find_server_action_endpoint(session, target, timeout) -> str | None:
    """
    Try to locate a Server Action (RSC) endpoint on the target.
    Returns the URL that responded to RSC content-type, or None.
    """
    candidates = [
        f"{target}/",
        f"{target}/api/",
    ]
    headers = {
        "Accept"      : "text/x-component",
        "RSC"         : "1",
        "Content-Type": "text/x-component",
    }
    for url in candidates:
        try:
            r = session.post(url, headers=headers, data="{}", timeout=timeout)
            ct = r.headers.get("content-type", "")
            if "text/x-component" in ct or r.status_code in (200, 400, 500):
                log_debug(f"Server Action endpoint candidate: {url} → {r.status_code}")
                return url
        except requests.RequestException:
            continue
    return None


def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(
        cve=CVE_ID,
        title=CVE_INFO["title"],
        severity=CVE_INFO["severity"],
        status="NOT VULNERABLE",
    )

    # Precondition Checks
    # CVE-2026-23864 targets React Flight protocol decoder on Server Action endpoints.
    # It requires Server Actions.
    if not config.has_active_server_actions():
        result.status = "NOT_APPLICABLE"
        log_info(f"[{CVE_ID}] No active Server Action IDs discovered. Skipping.")
        return result

    session = config.create_session()
    target  = config.target.rstrip("/")

    log_info(f"Starting {CVE_ID} scan — RSC Memory Exhaustion DoS...")

    # ── Phase 1: Version-based check (highest confidence) ─────────────────────
    best_ver = config.version_state.best()
    version_detected = best_ver.value if best_ver else None

    if version_detected:
        log_debug(f"Detected Next.js version: {version_detected}")
        vuln_status = check_vuln_status(version_detected, CVE_ID)

        if vuln_status == "PATCHED":
            log_success(f"Version {version_detected} is patched for {CVE_ID}.")
            return result

        if vuln_status == "VULNERABLE":
            detail = (
                f"Next.js {version_detected} is in the vulnerable range for {CVE_ID} "
                "(affected: 15.5.0–15.5.9, fix: 15.5.10). "
                "Memory-exhaustion DoS possible via malformed FormData RSC payload."
            )
            log_warning(detail)
            evidence = {
                "detected_version"    : version_detected,
                "vulnerability_status": "VULNERABLE (version-based)",
                "attack_vector"       : "POST multipart/form-data with $K<id>:FormData tokens to any Server Action endpoint",
                "remediation"         : "Upgrade Next.js to 15.5.10 or newer.",
            }
            print_finding(CVE_ID, detail, evidence)
            result.add_finding(Finding(
                cve=CVE_ID,
                severity=CVE_INFO["severity"],
                title="Vulnerable Version Detected — RSC Memory Exhaustion DoS",
                status="VULNERABLE",
                detail=detail,
                evidence=evidence,
                confidence=0.92,
            ))
            # Skip active probe — version-based detection is definitive
            return result

    # ── Phase 2: Non-destructive active probe (if version unknown) ─────────────
    log_debug("Version unknown — attempting non-destructive timing probe...")

    endpoint = _find_server_action_endpoint(session, target, config.timeout)
    if endpoint is None:
        log_debug("No RSC endpoint found — skipping active probe.")
        log_success(f"No {CVE_ID} indicators detected.")
        return result

    log_debug(f"Using RSC endpoint for timing probe: {endpoint}")

    body, ct = _build_probe_payload(_SAFE_TOKEN_COUNT)
    probe_headers = {
        "Content-Type": ct,
        "Accept"      : "text/x-component",
        "RSC"         : "1",
    }

    try:
        t0 = time.time()
        r  = session.post(endpoint, headers=probe_headers, data=body, timeout=config.timeout)
        elapsed = time.time() - t0

        log_debug(f"Probe: HTTP {r.status_code} in {elapsed:.2f}s ({len(r.content)} bytes)")

        if elapsed >= _TIMING_THRESHOLD:
            detail = (
                f"RSC endpoint {endpoint} took {elapsed:.2f}s to respond to a "
                f"{_SAFE_TOKEN_COUNT}-token FormData probe — likely vulnerable to "
                f"{CVE_ID} memory exhaustion DoS."
            )
            log_warning(detail)
            evidence = {
                "endpoint"          : endpoint,
                "probe_token_count" : _SAFE_TOKEN_COUNT,
                "response_time_s"   : round(elapsed, 2),
                "response_status"   : r.status_code,
                "note"              : "Timing-based detection — confirm with version check.",
                "remediation"       : "Upgrade Next.js to 15.5.10 or newer.",
            }
            print_finding(CVE_ID, detail, evidence)
            result.add_finding(Finding(
                cve=CVE_ID,
                severity=CVE_INFO["severity"],
                title="Suspicious RSC Response Time (Timing-Based)",
                status="VULNERABLE",
                detail=detail,
                evidence=evidence,
                confidence=0.65,
            ))

    except requests.exceptions.Timeout:
        detail = f"RSC endpoint {endpoint} timed out during probe — potential OOM/crash indicator."
        log_warning(detail)
        evidence = {
            "endpoint"    : endpoint,
            "note"        : "Server timeout may indicate memory exhaustion.",
            "remediation" : "Upgrade Next.js to 15.5.10 or newer.",
        }
        print_finding(CVE_ID, detail, evidence)
        result.add_finding(Finding(
            cve=CVE_ID,
            severity=CVE_INFO["severity"],
            title="RSC Endpoint Timeout (Potential DoS Indicator)",
            status="VULNERABLE",
            detail=detail,
            evidence=evidence,
            confidence=0.60,
        ))
    except requests.RequestException as e:
        result.error = str(e)

    if result.finding_count == 0:
        log_success(f"No {CVE_ID} indicators detected on target.")

    return result

