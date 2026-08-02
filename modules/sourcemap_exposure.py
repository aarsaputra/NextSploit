#!/usr/bin/env python3
"""
NextSploit — Sourcemap Exposure Scanner

Detects publicly accessible JavaScript sourcemaps (.js.map) in Next.js applications.
Exposed sourcemaps reveal full source code including React components, route handlers,
server-side logic, authentication flows, and sometimes hardcoded secrets.

This is often more impactful than CVE-based code exposure because:
  - Very common misconfiguration in production
  - No specific Next.js version requirement
  - Provides full source code without authentication

References:
  - OWASP: Source Code Exposure
  - CWE-540: Inclusion of Sensitive Information in Source Code
"""

import re
import json
import requests

from core.config import ScanConfig
from core.reporter import ModuleResult, Finding, ScanStatus
from core.output import (
    log_info, log_success, log_warning, log_critical, log_debug,
    log_trace, log_error, print_module_header, print_finding,
    create_progress,
)
from core.fp_engine import is_waf_block

MODULE_NAME = "SOURCEMAP-EXPOSURE"
MODULE_TITLE = "JavaScript Sourcemap Public Exposure"
MODULE_SEVERITY = "HIGH"

# Known Next.js chunk paths that commonly expose sourcemaps
KNOWN_CHUNK_PATHS = [
    "/_next/static/chunks/main.js",
    "/_next/static/chunks/webpack.js",
    "/_next/static/chunks/pages/_app.js",
    "/_next/static/chunks/pages/_error.js",
    "/_next/static/chunks/app/layout.js",
    "/_next/static/chunks/app/page.js",
    "/_next/static/chunks/framework.js",
    "/_next/static/chunks/polyfills.js",
]

# Secrets patterns to scan for in exposed sourcemap content
SECRET_PATTERNS = [
    (re.compile(r'NEXT_PUBLIC_[A-Z_]{3,}=["\']?([^"\'\\n]{8,})', re.I), "NEXT_PUBLIC_ env var"),
    (re.compile(r'"(api[_-]?key|apikey|api_token|access_token|secret[_-]?key)"\s*:\s*"([^"]{8,})"', re.I), "API key/secret"),
    (re.compile(r'process\.env\.[A-Z_]{3,}', re.I), "process.env reference"),
    (re.compile(r'https?://[a-z0-9.-]+\.(internal|local|corp|intranet|private)', re.I), "Internal URL"),
    (re.compile(r'(?:mongodb|postgresql|mysql|redis|amqp)s?://[^\s"\']{10,}', re.I), "Database connection string"),
]


def _is_valid_sourcemap(text: str) -> bool:
    """
    Validate that a response is actually a sourcemap JSON, not a soft-404 or WAF page.
    A valid sourcemap must have 'version', 'sources', and 'mappings' fields.
    """
    if not text or len(text) < 100:
        return False

    # Fast reject: if it looks like HTML
    stripped = text.strip().lower()
    if stripped.startswith(("<!doctype", "<html", "<head", "<?xml")):
        return False

    try:
        data = json.loads(text[:100000])  # Only parse first 100KB
        return (
            isinstance(data, dict)
            and data.get("version") == 3
            and "sources" in data
            and "mappings" in data
        )
    except (json.JSONDecodeError, ValueError):
        return False


def _scan_sourcemap_content(content: str) -> list:
    """
    Scan sourcemap content for leaked secrets and sensitive references.
    Returns list of (pattern_name, match) tuples.
    """
    findings = []
    for pattern, name in SECRET_PATTERNS:
        matches = pattern.findall(content[:500000])  # Limit to 500KB
        if matches:
            # Deduplicate
            unique = list(set(str(m) for m in matches[:5]))
            findings.append((name, unique))
    return findings


def scan(config: ScanConfig) -> ModuleResult:
    """
    Scan for exposed JavaScript sourcemaps in Next.js applications.

    Strategy:
    1. Check known Next.js chunk paths for .map files
    2. Extract JS chunk URLs from fingerprint data and probe each for .map
    3. Validate responses are real sourcemaps (not soft-404/WAF blocks)
    4. Scan content for leaked secrets / env vars / internal URLs
    """
    result = ModuleResult(
        cve=MODULE_NAME,
        title=MODULE_TITLE,
        severity=MODULE_SEVERITY,
        status=ScanStatus.SAFE,
    )

    print_module_header(MODULE_NAME, MODULE_TITLE, MODULE_SEVERITY)
    session = config.create_session()
    target = config.target.rstrip("/")

    # ── Build list of .js chunks to probe ────────────────────────────────────
    # Start with known paths
    chunks_to_probe = list(KNOWN_CHUNK_PATHS)

    # Add chunks discovered during fingerprinting
    if config.discovered_js_chunks:
        chunks_to_probe.extend(config.discovered_js_chunks)
        log_info(f"Added {len(config.discovered_js_chunks)} fingerprinted JS chunks to probe list")

    # If we have a build ID, add hashed chunk paths
    if config.discovered_build_id:
        bid = config.discovered_build_id
        chunks_to_probe.extend([
            f"/_next/static/{bid}/_buildManifest.js",
            f"/_next/static/{bid}/_ssgManifest.js",
        ])

    # Deduplicate and convert to .map paths
    seen = set()
    map_paths = []
    for chunk in chunks_to_probe:
        map_path = chunk if chunk.endswith(".map") else f"{chunk}.map"
        if map_path not in seen:
            seen.add(map_path)
            map_paths.append(map_path)

    log_info(f"Probing {len(map_paths)} potential sourcemap paths...")

    # ── Probe each .map path ─────────────────────────────────────────────────
    found_count = 0

    with create_progress() as progress:
        task = progress.add_task("Sourcemap Probe", total=len(map_paths))

        for map_path in map_paths:
            progress.update(task, advance=1)

            # Safety: respect max_requests_per_module
            if config.max_requests_per_module > 0 and config.total_request_count() >= config.max_requests_per_module:
                log_warning(f"max-requests limit reached ({config.max_requests_per_module}) — stopping sourcemap scan")
                break

            try:
                r = session.get(
                    f"{target}{map_path}",
                    timeout=config.timeout,
                    headers={"Accept": "application/json, */*"},
                )

                log_trace(f"[{r.status_code}] {map_path}")

                # Skip WAF blocks
                if is_waf_block(r):
                    log_debug(f"WAF block on {map_path} — skipped")
                    continue

                # Skip 404s and non-200
                if r.status_code != 200:
                    continue

                # Validate it's a real sourcemap
                if not _is_valid_sourcemap(r.text):
                    log_debug(f"Not a valid sourcemap: {map_path} ({r.status_code}, {len(r.text)} bytes)")
                    continue

                found_count += 1
                size_kb = len(r.text) // 1024

                # Parse for source file list
                try:
                    sm_data = json.loads(r.text[:200000])
                    source_files = sm_data.get("sources", [])
                    has_source_content = bool(sm_data.get("sourcesContent"))
                    source_preview = source_files[:10]
                except Exception:
                    source_files = []
                    has_source_content = False
                    source_preview = []

                # Scan for secrets
                secret_hits = _scan_sourcemap_content(r.text)

                severity = "CRITICAL" if (has_source_content or secret_hits) else "HIGH"
                detail = (
                    f"Sourcemap exposed: {map_path} "
                    f"({size_kb}KB, {len(source_files)} source files"
                    + (", includes sourcesContent" if has_source_content else "")
                    + ")"
                )
                log_critical(detail) if severity == "CRITICAL" else log_warning(detail)

                evidence = {
                    "path": map_path,
                    "size_kb": size_kb,
                    "source_file_count": len(source_files),
                    "has_source_content": has_source_content,
                    "source_files_preview": source_preview,
                    "cwe": "CWE-540",
                    "impact": (
                        "Full application source code exposed. Attackers can analyze "
                        "authentication logic, route structure, API endpoints, and secrets."
                    ),
                }

                if secret_hits:
                    evidence["leaked_secrets"] = [
                        {"type": name, "samples": samples}
                        for name, samples in secret_hits
                    ]
                    log_critical(f"Sensitive data found in sourcemap: {[n for n, _ in secret_hits]}")

                # Save evidence
                safe_name = map_path.replace("/", "_").lstrip("_")
                saved_path = config.save_response(f"sourcemap_{safe_name}", r)
                if saved_path:
                    evidence["saved_to"] = saved_path

                print_finding(MODULE_NAME, detail, evidence)
                result.add_finding(Finding(
                    cve=MODULE_NAME,
                    severity=severity,
                    title="JavaScript Sourcemap Exposed",
                    status=ScanStatus.VULNERABLE,
                    detail=detail,
                    evidence=evidence,
                ))

            except requests.RequestException as e:
                log_trace(f"Request error probing {map_path}: {e}")

    # ── Summary ───────────────────────────────────────────────────────────────
    if found_count > 0:
        log_warning(f"Found {found_count} exposed sourcemap(s) — source code disclosure confirmed")
    else:
        log_success("No exposed sourcemaps found")

    return result
