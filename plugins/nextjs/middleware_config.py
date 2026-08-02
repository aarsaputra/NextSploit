"""
plugins/nextjs/middleware_config.py — Middleware Configuration Auditor

Black-box analysis approach (no source code access required):
1. Probe /_next/server/middleware-manifest.json for exposed matchers.
2. Probe /__nextjs_original-stack-frame for debug endpoint exposure.
3. Check response headers for middleware execution signals.
4. Detect overly broad matcher patterns (e.g. matching all routes).

Detection type: passive (no auth bypass attempt, no active exploit).
"""

import json
import re
from typing import Any, List


# Patterns considered dangerous in middleware matchers
_BROAD_MATCHER_PATTERNS = [
    r"^\/$",            # Matches root only — often too narrow, but common
    r"^\/\.\*$",        # Matches everything — overly broad
    r"^\(.*\)\/",       # Complex group matchers without specific paths
]

_DANGEROUS_REWRITE_PATTERNS = [
    r"destination.*external",
    r"destination.*https?://",
]


class MiddlewareConfigPlugin:
    """
    Passive auditor for Next.js middleware configuration.
    Looks for exposed configuration and potentially dangerous patterns via black-box probing.
    """

    id = "next.middleware.config"
    name = "Middleware Configuration Auditor"
    manifest = {}

    def initialize(self, context: Any) -> None:
        self._context = context
        self._findings: List[Any] = []

    def precondition(self, context: Any) -> bool:
        # Only run if middleware capability is confirmed
        return getattr(context.profile, "middleware", False)

    def execute(self, context: Any) -> None:
        session = context.session
        base = context.profile.target_url.rstrip("/")

        # 1. Try to fetch middleware manifest (sometimes publicly accessible)
        self._probe_manifest(session, base, context)

        # 2. Check for debug endpoint exposure
        self._probe_debug_endpoint(session, base, context)

        # 3. Analyze existing response headers for signals
        self._analyze_response_headers(context)

    def _probe_manifest(self, session: Any, base: str, context: Any) -> None:
        paths_to_try = [
            "/_next/server/middleware-manifest.json",
            "/_next/static/chunks/middleware.js",
        ]
        for path in paths_to_try:
            try:
                resp = session.get(f"{base}{path}", timeout=8)
                if resp.status_code == 200:
                    content_type = resp.headers.get("content-type", "")
                    if "json" in content_type or path.endswith(".json"):
                        self._analyze_manifest_json(resp.text, path, context)
                    elif path.endswith(".js"):
                        self._analyze_middleware_js(resp.text, path, context)
            except Exception:
                pass

    def _analyze_manifest_json(self, body: str, path: str, context: Any) -> None:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return

        matchers = data.get("matchers", []) or data.get("matcher", [])
        if not isinstance(matchers, list):
            matchers = [matchers]

        for matcher in matchers:
            regexp = matcher.get("regexp", "") if isinstance(matcher, dict) else str(matcher)
            if any(re.search(p, regexp) for p in _BROAD_MATCHER_PATTERNS):
                self._add_finding(
                    context,
                    title="Overly Broad Middleware Matcher Detected",
                    severity="medium",
                    detail=f"Middleware matcher '{regexp}' may apply to unintended routes, "
                           f"increasing attack surface for bypass attempts.",
                    path=path,
                )

        # Exposed manifest is itself information disclosure
        self._add_finding(
            context,
            title="Middleware Manifest Publicly Accessible",
            severity="low",
            detail=f"The file '{path}' is publicly accessible. It reveals middleware "
                   f"routing configuration which can assist targeted attacks.",
            path=path,
        )

    def _analyze_middleware_js(self, body: str, path: str, context: Any) -> None:
        # Look for patterns indicating header-based auth that might be bypassed
        dangerous_patterns = [
            (r"x-forwarded-user", "Middleware trusts x-forwarded-user header without validation"),
            (r"x-user-role", "Middleware trusts x-user-role header without validation"),
            (r"x-internal", "Middleware references x-internal header — potential trust boundary issue"),
        ]
        for pattern, message in dangerous_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                self._add_finding(
                    context,
                    title="Potentially Unsafe Header Trust in Middleware",
                    severity="high",
                    detail=f"{message}. Attackers can forge these headers if not validated at CDN/WAF.",
                    path=path,
                )

    def _probe_debug_endpoint(self, session: Any, base: str, context: Any) -> None:
        debug_paths = [
            "/__nextjs_original-stack-frame",
            "/__nextjs_launch-editor",
        ]
        for path in debug_paths:
            try:
                resp = session.get(f"{base}{path}", timeout=5)
                if resp.status_code in (200, 400):  # 400 = exists but wrong params
                    self._add_finding(
                        context,
                        title="Next.js Debug Endpoint Exposed in Production",
                        severity="medium",
                        detail=f"Debug endpoint '{path}' is accessible. This endpoint is intended "
                               f"for development only and may expose internal stack frames or "
                               f"allow arbitrary file reads in certain configurations.",
                        path=path,
                    )
            except Exception:
                pass

    def _analyze_response_headers(self, context: Any) -> None:
        headers = getattr(context.profile, "headers", {}) or {}
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Check if x-powered-by reveals version info
        powered_by = headers_lower.get("x-powered-by", "")
        if "next.js" in powered_by.lower():
            version_in_header = re.search(r"[\d]+\.[\d]+\.[\d]+", powered_by)
            if version_in_header:
                self._add_finding(
                    context,
                    title="Next.js Version Disclosed in X-Powered-By Header",
                    severity="info",
                    detail=f"Version '{version_in_header.group()}' is disclosed via X-Powered-By header. "
                           f"Remove or obfuscate this header in production (next.config.js: poweredByHeader: false).",
                    path="<response headers>",
                )

    def _add_finding(self, context: Any, title: str, severity: str, detail: str, path: str) -> None:
        from nextsploit.services.reporter import Finding
        finding = Finding(
            id=self.id,
            title=title,
            severity=severity,
            confidence=0.75,
            evidence={
                "source": "plugin",
                "detection_type": "passive",
                "plugin_id": self.id,
                "path": path,
                "detail": detail,
            },
            remediation="Review middleware configuration. Restrict matchers to specific paths. "
                        "Do not expose configuration files in production environments.",
        )
        context.reporter.add_finding(finding)
        self._findings.append(finding)

    def collect(self, context: Any) -> None:
        pass

    def validate(self, context: Any) -> None:
        pass

    def report(self, context: Any) -> None:
        pass

    def cleanup(self, context: Any) -> None:
        self._findings = []
