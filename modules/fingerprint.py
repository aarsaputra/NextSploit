#!/usr/bin/env python3
"""
NextSploit — Next.js Fingerprinting Module v2
Detects version, build ID, Server Action IDs, and maps vulnerability status.

Improvements over v1:
  - CDN URL pattern extraction for Build ID (productionassets CDN)
  - <link> stylesheet href extraction
  - Server Action ID discovery from JS bundles
  - Discovered data propagated to ScanConfig for cross-module use
"""

import re
import requests

from core.config import ScanConfig, CVE_DATABASE, check_vuln_status
from core.output import (
    log_info, log_success, log_warning, log_debug, log_trace,
    log_error, print_section, print_vuln_matrix,
)


# ─── WAF / CDN Detection Signatures ─────────────────────────────────────────

WAF_CDN_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "server": ["cloudflare"],
        "body": ["cloudflare ray id", "__cf_chl"],
    },
    "Akamai": {
        "headers": ["x-check-cacheable", "x-akamai-transformed", "akamai-origin-hop", "c-via"],
        "server": ["akamaighost", "akamai"],
        "body": ["akamai reference"],
    },
    "Fastly": {
        "headers": ["x-fastly-request-id", "fastly-debug-digest", "x-served-by"],
        "server": ["fastly"],
        "body": [],
    },
    "AWS CloudFront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop"],
        "server": ["cloudfront"],
        "body": [],
    },
    "Vercel": {
        "headers": ["x-vercel-id", "x-vercel-cache", "x-vercel-signature"],
        "server": ["vercel"],
        "body": [],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["sucuri"],
        "body": ["sucuri website firewall"],
    },
    "Imperva / Incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "server": ["imperva", "incapsula"],
        "body": ["incapsula incident"],
    },
    "Whaleguard": {
        "headers": [],
        "server": [],
        "body": ["whaleguard block"],
    },
}


def detect_waf_cdn(response_headers: dict, response_body: str = "") -> list:
    """
    Detect WAF/CDN presence from HTTP response headers and body.

    Returns:
        list of detected WAF/CDN names (may be empty)
    """
    detected = []
    headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
    body_lower = response_body[:2000].lower()

    for name, sigs in WAF_CDN_SIGNATURES.items():
        matched = False

        # Check headers
        for h in sigs.get("headers", []):
            if h.lower() in headers_lower:
                matched = True
                break

        # Check Server header
        if not matched:
            server_val = headers_lower.get("server", "")
            for s in sigs.get("server", []):
                if s.lower() in server_val:
                    matched = True
                    break

        # Check body patterns
        if not matched:
            for bp in sigs.get("body", []):
                if bp.lower() in body_lower:
                    matched = True
                    break

        if matched:
            detected.append(name)

    return detected


# ─── CDN / Build ID patterns ─────────────────────────────────────────────────

# Matches /_next/static/<build_id>/
BUILD_ID_NEXT_STATIC = re.compile(r'/_next/static/([a-zA-Z0-9_-]{8,})/')

# Matches CDN URLs like: productionassets.rollercoin.com/next-app/<build_id>/
BUILD_ID_CDN = re.compile(
    r'https?://[^/]+/next-app/([a-zA-Z0-9_-]{16,})/'
)

# Matches stylesheet links with full CDN path
BUILD_ID_LINK_HREF = re.compile(
    r'<link[^>]+href="[^"]*/_next/static/([a-zA-Z0-9_-]{8,})/'
)

# Server Action IDs: 8-char hex strings in Next-Action context or as map keys
ACTION_ID_PATTERNS = [
    # Inline hex IDs in action map definitions
    re.compile(r'["\']([0-9a-f]{40})["\']'),            # 40-char SHA1-like
    re.compile(r'["\']([0-9a-f]{8,16})["\']'),          # 8–16 char hex
    re.compile(r'Next-Action["\s:]+["\']([0-9a-f]+)["\']'),
    re.compile(r'ACTION_ID_([0-9a-f]+)'),
]


def fingerprint(config: ScanConfig) -> dict:
    """
    Fingerprint a Next.js target.

    Returns:
        dict with keys: version, build_id, vuln_matrix, headers,
                        technologies, action_ids, waf_cdn
    """
    result = {
        "version": None,
        "build_id": None,
        "vuln_matrix": [],
        "headers": {},
        "technologies": [],
        "action_ids": [],
        "waf_cdn": [],
    }

    session = config.create_session()
    target = config.target.rstrip("/")

    print_section("Next.js Fingerprinting", f"Target: {target}")

    # ════════════════════════════════════════════════════════════════════
    # Phase 0: Pre-Scan Triage — WAF/CDN Detection
    # ════════════════════════════════════════════════════════════════════
    log_info("[Phase 0] Pre-scan triage: WAF/CDN detection...")
    try:
        config.throttle()
        r_triage = session.get(target, timeout=config.timeout, allow_redirects=True)
        config.record_request(r_triage.status_code)
        triage_headers = dict(r_triage.headers)
        triage_body = r_triage.text

        detected_waf = detect_waf_cdn(triage_headers, triage_body)
        if detected_waf:
            result["waf_cdn"] = detected_waf
            # Store on config for all modules to access
            config.detected_waf = detected_waf
            for waf_name in detected_waf:
                log_warning(
                    f"[Phase 0] Detected: [bold yellow]{waf_name}[/bold yellow] — "
                    f"timing/SSRF/cache modules may return INCONCLUSIVE. "
                    f"Consider scanning the origin IP directly with: "
                    f"-t http://ORIGIN_IP -H \"Host: {target.split('//')[-1]}\""
                )
        else:
            log_success("[Phase 0] No CDN/WAF detected — direct connection likely")
            config.detected_waf = []

    except requests.RequestException as e:
        log_error(f"[Phase 0] Pre-scan triage failed: {e}")
        config.detected_waf = []
        triage_headers = {}
        triage_body = ""

    # ════════════════════════════════════════════════════════════════════
    # Step 1: Fetch main page
    # ════════════════════════════════════════════════════════════════════
    try:
        config.throttle()
        r = session.get(target, timeout=config.timeout)
        config.record_request(r.status_code)
        result["headers"] = dict(r.headers)
        config.last_response_headers = dict(r.headers)
        log_debug(f"Status: {r.status_code} | Size: {len(r.text)} bytes")
    except requests.RequestException as e:
        log_error(f"Cannot reach target: {e}")
        return result

    page_text = r.text
    # Normalize escaped slashes (e.g. from inline scripts / RSC payloads)
    normalized_page_text = page_text.replace('\\/', '/')

    # Extract all JS and CSS chunks from page source (capturing those in inline scripts)
    js_chunk_paths = list(set(re.findall(r'(/_next/static/[^\s"\'\\{}()<>]+.js)', normalized_page_text)))
    css_chunk_paths = list(set(re.findall(r'(/_next/static/[^\s"\'\\{}()<>]+.css)', normalized_page_text)))
    config.discovered_js_chunks = js_chunk_paths
    config.discovered_css_chunks = css_chunk_paths

    # Simple router type deduction from page text
    if "/_next/static/chunks/app/" in normalized_page_text or "/_next/static/css/app/" in normalized_page_text:
        config.detected_router_type = "app"
    elif "/_next/static/chunks/pages/" in normalized_page_text or "/_next/static/css/pages/" in normalized_page_text:
        config.detected_router_type = "pages"

    # Log hosting infrastructure
    if config.has_managed_hosting():
        log_success("[*] Hosting detected: [bold cyan]Vercel (managed)[/bold cyan] — platform-level protections active")
    else:
        log_info("[*] Hosting detected: Self-hosted / unknown")

    # ─── Step 2: Detect version from headers ─────────────────────────────
    log_info("Checking response headers...")

    powered_by = r.headers.get("X-Powered-By", "")
    if "next" in powered_by.lower():
        log_success(f"X-Powered-By: [bold]{powered_by}[/bold]")
        result["technologies"].append(f"X-Powered-By: {powered_by}")
        # Try extracting version (e.g. Next.js 14.2.3)
        ver_match = re.search(r'next\.js\s*v?(\d+\.\d+\.\d+)', powered_by, re.IGNORECASE)
        if ver_match:
            ver = ver_match.group(1)
            config.report_version(ver, 0.8, "header")
            result["version"] = ver

    server = r.headers.get("Server", "")
    if server:
        log_debug(f"Server: {server}")
        result["technologies"].append(f"Server: {server}")

    nextjs_cache = r.headers.get("x-nextjs-cache", "")
    if nextjs_cache:
        log_success(f"X-Nextjs-Cache: [bold]{nextjs_cache}[/bold] (confirms Next.js)")
        result["technologies"].append("X-Nextjs-Cache present")

    # ─── Step 3: Extract Build ID (multi-strategy) ───────────────────────
    log_info("Extracting Build ID (multi-strategy)...")

    build_id = None
    build_id_source = None

    # Strategy 1: /_next/static/<build_id>/
    ids = BUILD_ID_NEXT_STATIC.findall(page_text)
    if ids:
        build_id = max(set(ids), key=ids.count)
        build_id_source = "_next/static path"

    # Strategy 2: CDN URL pattern (productionassets / cloudfront / etc.)
    if not build_id:
        cdn_ids = BUILD_ID_CDN.findall(page_text)
        if cdn_ids:
            build_id = max(set(cdn_ids), key=cdn_ids.count)
            build_id_source = "CDN URL"

    # Strategy 3: <link href=".../_next/static/<build_id>/...">
    if not build_id:
        link_ids = BUILD_ID_LINK_HREF.findall(page_text)
        if link_ids:
            build_id = max(set(link_ids), key=link_ids.count)
            build_id_source = "<link> href"

    if build_id:
        result["build_id"] = build_id
        log_success(f"Build ID: [bold cyan]{build_id}[/bold cyan] [dim](from {build_id_source})[/dim]")
        # Share with config for cross-module use
        config.discovered_build_id = build_id
        # Report buildid signal (but note: Build ID itself is not a version string,
        # so we don't call config.report_version() with buildid yet, unless we map it.
        # But wait, if buildid contains the version directly? No, usually it is a hash or string.
        # However, some buildids are versions, but we should not blindly report them as version.)
    else:
        log_warning("Could not extract Build ID from page source")

    # ─── Step 4: Detect version from __NEXT_DATA__ ───────────────────────
    log_info("Checking __NEXT_DATA__ script...")
    next_data_match = re.search(
        r'<script\s+id="__NEXT_DATA__"[^>]*>(.*?)</script>',
        page_text, re.DOTALL
    )
    if next_data_match:
        try:
            import json
            next_data = json.loads(next_data_match.group(1))
            if "buildId" in next_data:
                nd_bid = next_data["buildId"]
                result["build_id"] = nd_bid
                config.discovered_build_id = nd_bid
                log_success(f"Build ID (__NEXT_DATA__): [bold cyan]{nd_bid}[/bold cyan]")
                # If buildid looks like a version (e.g. 14.2.3), report it
                if re.match(r'^\d+\.\d+\.\d+$', nd_bid):
                    config.report_version(nd_bid, 0.95, "buildid")
                    if not result["version"]:
                        result["version"] = nd_bid

            if "runtimeConfig" in next_data.get("props", {}).get("pageProps", {}):
                log_debug("runtimeConfig found in pageProps")

            log_trace(f"__NEXT_DATA__ keys: {list(next_data.keys())}")
        except Exception:
            log_debug("Could not parse __NEXT_DATA__ JSON")
    else:
        log_debug("No __NEXT_DATA__ script found")

    # ─── Step 5: Probe known Next.js indicator paths ─────────────────────
    log_info("Probing Next.js indicator paths...")
    indicator_paths = [
        ("/_next/static/chunks/webpack.js", "Webpack chunks (Next.js)"),
        ("/_next/static/chunks/main.js", "Main bundle"),
        ("/_next/static/chunks/pages/_app.js", "Pages router (_app.js)"),
        ("/_next/static/chunks/app/layout.js", "App router (layout.js)"),
        ("/_next/image?url=/&w=1&q=1", "Next.js Image Optimization API"),
    ]

    js_chunks_to_scan = []
    for path, desc in indicator_paths:
        try:
            config.throttle()
            r2 = session.get(f"{target}{path}", timeout=config.timeout)
            config.record_request(r2.status_code)
            if r2.status_code == 200:
                log_success(f"Found: {desc} [dim]({path})[/dim]")
                result["technologies"].append(desc)

                if path == "/_next/static/chunks/pages/_app.js":
                    config.detected_router_type = "pages"
                elif path == "/_next/static/chunks/app/layout.js":
                    config.detected_router_type = "app"

                if path.endswith(".js"):
                    js_chunks_to_scan.append((path, r2.text))
                    ver_match = re.search(r'Next\.js\s*v?(\d+\.\d+\.\d+)', r2.text)
                    if ver_match:
                        ver = ver_match.group(1)
                        config.report_version(ver, 0.9, "chunk_js")
                        if not result["version"]:
                            result["version"] = ver
                            log_success(
                                f"Version from JS: [bold green]{result['version']}[/bold green]"
                            )
            else:
                log_debug(f"[{r2.status_code}] {path}")
        except requests.RequestException as e:
            log_trace(f"Network error probing indicator path {path}: {e}")

    # ─── Step 6: Version detection from JS chunks ────────────────────────
    if not result["version"]:
        log_info("Attempting version detection from JS chunks...")

        # Prioritize chunks that likely contain framework/version information
        def chunk_priority(path: str) -> int:
            path_lower = path.lower()
            if "framework" in path_lower:
                return 0
            if "main" in path_lower:
                return 1
            if "webpack" in path_lower:
                return 2
            if "core" in path_lower:
                return 3
            if "layout" in path_lower:
                return 4
            if "_app" in path_lower:
                return 5
            return 10

        sorted_js_chunks = sorted(js_chunk_paths, key=chunk_priority)

        for chunk_path in sorted_js_chunks[:15]:
            try:
                config.throttle()
                r3 = session.get(f"{target}{chunk_path}", timeout=config.timeout)
                config.record_request(r3.status_code)
                if r3.status_code == 200:
                    js_chunks_to_scan.append((chunk_path, r3.text))
                    patterns = [
                        r'(?:"version"|\'version\'|version)\s*[:=]\s*["\'](\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?)["\']',
                        r'Next\.js\s*v?(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?\b)',
                        r'nextjs/(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?\b)',
                        r'window\.next\s*=\s*\{\s*version\s*:\s*["\'](\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?)["\']',
                    ]
                    for pat in patterns:
                        m = re.search(pat, r3.text)
                        if m:
                            ver = m.group(1)
                            config.report_version(ver, 0.9, "chunk_js")
                            result["version"] = ver
                            log_success(
                                f"Version from chunk: [bold green]{result['version']}[/bold green]"
                            )
                            break
                if result["version"]:
                    break
            except requests.RequestException as e:
                log_trace(f"Network error fetching chunk {chunk_path}: {e}")

    # ─── Step 7: Server Action ID Discovery ──────────────────────────────
    log_info("Scanning JS bundles for Server Action IDs...")
    found_action_ids = set()

    all_js_text = "\n".join(content for _, content in js_chunks_to_scan)
    if not all_js_text:
        all_js_text = page_text  # Fall back to page source

    for pat in ACTION_ID_PATTERNS:
        for match in pat.findall(all_js_text):
            candidate = match.strip()
            # Filter: must be hex, 8–40 chars, not a common false positive
            if (
                re.match(r'^[0-9a-f]{8,40}$', candidate)
                and candidate not in {"00000000", "ffffffff", "deadbeef"}
            ):
                found_action_ids.add(candidate)

    if found_action_ids:
        result["action_ids"] = sorted(found_action_ids)
        config.discovered_action_ids = list(found_action_ids)
        log_success(
            f"Found [bold]{len(found_action_ids)}[/bold] potential Server Action IDs"
        )
        for aid in sorted(found_action_ids)[:10]:  # Show first 10
            log_debug(f"  Action ID: {aid}")
        if len(found_action_ids) > 10:
            log_debug(f"  ... and {len(found_action_ids) - 10} more")
    else:
        log_debug("No Server Action IDs found in scanned JS bundles")

    # If any version has been reported, use the best one
    best_ver_sig = config.version_state.best()
    if best_ver_sig:
        result["version"] = best_ver_sig.value

    # ─── Step 8: Build vulnerability matrix ──────────────────────────────
    if result["version"]:
        log_info(f"Building vulnerability matrix for [bold]{result['version']}[/bold]...")
    else:
        log_warning("Version not detected — matrix will show UNKNOWN status")

    def _get_fix_version(cve_info: dict) -> str:
        """Safely extract a display string for fix version from either schema."""
        if "fix_version" in cve_info:
            return cve_info["fix_version"]
        if "ranges" in cve_info:
            # Join branch-specific fix versions: e.g. "15.5.21 / 16.2.11"
            return " / ".join(r["fix_version"] for r in cve_info["ranges"] if "fix_version" in r) or "N/A"
        return "N/A"

    for cve_id, cve_info in CVE_DATABASE.items():
        status = check_vuln_status(result["version"], cve_id) if result["version"] else "UNKNOWN"
        result["vuln_matrix"].append({
            "cve": cve_id,
            "type": cve_info.get("type", "N/A"),
            "fix_version": _get_fix_version(cve_info),
            "status": status,
        })

    print_vuln_matrix(result["vuln_matrix"])


    # Summary
    if result["version"]:
        vuln_count = sum(1 for v in result["vuln_matrix"] if "VULNERABLE" in v["status"])
        if vuln_count > 0:
            log_warning(
                f"Detected [bold]{vuln_count}[/bold] potential vulnerabilities "
                f"for Next.js {result['version']}"
            )
        else:
            log_success("No known vulnerabilities for this version")
    else:
        log_info("Manual version confirmation recommended")

    return result

