"""
plugins/nextjs/middleware_trust.py — Middleware Header Trust Pattern Detector

Detects when Next.js middleware passes internal/synthetic headers to the
application layer without proper validation — a black-box detection strategy
by probing for trusting behavior.

Pattern:
  Attacker sends: x-user-role: admin
  Middleware receives it and forwards unchanged → application trusts it

Detection approach:
  1. Send requests with forged internal headers.
  2. If the application behaves differently (200 vs 401/403), trust is confirmed.
  3. Also scan response body for echoed header values (reflection).
"""

import re
from typing import Any, Dict, List


# Headers that middleware should never blindly forward from external sources
_SUSPICIOUS_HEADERS = [
    ("x-user-role", "admin"),
    ("x-user-id", "1"),
    ("x-admin", "true"),
    ("x-forwarded-user", "admin@internal.com"),
    ("x-internal-token", "trusted"),
    ("x-bypass-auth", "1"),
    ("x-authenticated", "true"),
    ("x-tenant-admin", "true"),
]

# Common protected endpoints to probe
_PROBE_PATHS = [
    "/api/admin",
    "/api/user",
    "/dashboard",
    "/admin",
    "/api/me",
]


class MiddlewareTrustPlugin:
    """
    Detects blind header trust in Next.js middleware via differential response analysis.
    Sends requests with and without forged privilege-escalation headers and compares responses.
    """

    id = "next.middleware.trust"
    name = "Middleware Header Trust Detector"
    manifest = {}

    def initialize(self, context: Any) -> None:
        self._context = context
        self._findings: List[Any] = []

    def precondition(self, context: Any) -> bool:
        return getattr(context.profile, "middleware", False)

    def execute(self, context: Any) -> None:
        session = context.session
        base = context.profile.target_url.rstrip("/")

        for path in _PROBE_PATHS:
            url = f"{base}{path}"
            self._probe_path(session, url, path, context)

    def _probe_path(self, session: Any, url: str, path: str, context: Any) -> None:
        # Baseline: request without any forged headers
        try:
            baseline_resp = session.get(url, timeout=8)
            baseline_status = baseline_resp.status_code
        except Exception:
            return

        # Only interesting if baseline is protected (401 or 403)
        if baseline_status not in (401, 403):
            return

        # Now try each forged header
        for header_name, header_value in _SUSPICIOUS_HEADERS:
            try:
                forged_resp = session.get(
                    url,
                    headers={header_name: header_value},
                    timeout=8,
                )
            except Exception:
                continue

            forged_status = forged_resp.status_code

            # If forged request returns 200 but baseline was 401/403 → trust issue confirmed
            if forged_status == 200 and baseline_status in (401, 403):
                self._add_finding(
                    context,
                    severity="high",
                    path=path,
                    header_name=header_name,
                    header_value=header_value,
                    baseline_status=baseline_status,
                    forged_status=forged_status,
                    detail=(
                        f"Sending '{header_name}: {header_value}' to '{path}' changed "
                        f"response from {baseline_status} to {forged_status}. "
                        f"Middleware appears to trust externally-supplied privilege headers."
                    ),
                )
                break  # One finding per path is sufficient

            # Also check for reflection — header value echoed in body
            if header_value.lower() in forged_resp.text.lower():
                self._add_finding(
                    context,
                    severity="medium",
                    path=path,
                    header_name=header_name,
                    header_value=header_value,
                    baseline_status=baseline_status,
                    forged_status=forged_status,
                    detail=(
                        f"Header value '{header_value}' was reflected in the response body "
                        f"of '{path}' when '{header_name}' was set. "
                        f"This indicates the application reads and uses the header value."
                    ),
                )

    def _add_finding(
        self,
        context: Any,
        severity: str,
        path: str,
        header_name: str,
        header_value: str,
        baseline_status: int,
        forged_status: int,
        detail: str,
    ) -> None:
        from nextsploit.services.reporter import Finding
        finding = Finding(
            id=self.id,
            title="Middleware Blindly Trusts Externally-Supplied Privilege Headers",
            severity=severity,
            confidence=0.85,
            evidence={
                "source": "plugin",
                "detection_type": "differential",
                "plugin_id": self.id,
                "path": path,
                "forged_header": {header_name: header_value},
                "baseline_status": baseline_status,
                "forged_status": forged_status,
                "detail": detail,
            },
            cwe="CWE-807",
            owasp="A01:2021",
            remediation=(
                "Do not trust headers like x-user-role, x-admin, or x-forwarded-user "
                "if they originate from external requests. "
                "Strip these headers at the CDN/load balancer layer before they reach your middleware. "
                "In Next.js middleware, use `request.nextUrl` and session cookies — "
                "never rely on internal headers that could be forged."
            ),
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
