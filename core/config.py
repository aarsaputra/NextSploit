#!/usr/bin/env python3
"""
NextSploit — Core Configuration & Shared Resources
"""

from dataclasses import dataclass, field
from typing import Optional
import requests
import urllib3

# Suppress InsecureRequestWarning for --no-verify scenarios
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─── CVE Database ────────────────────────────────────────────────────────────

CVE_DATABASE = {
    "CVE-2025-29927": {
        "id": "CVE-2025-29927",
        "short": "29927",
        "title": "Middleware Authorization Bypass",
        "type": "Auth Bypass",
        "severity": "CRITICAL",
        "fix_version": "14.2.25",
        "description": (
            "Next.js middleware can be bypassed via the x-middleware-subrequest "
            "header, allowing unauthenticated access to protected routes."
        ),
        "references": [
            "https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw",
        ],
    },
    "CVE-2025-57822": {
        "id": "CVE-2025-57822",
        "short": "57822",
        "title": "Server-Side Request Forgery (SSRF)",
        "type": "SSRF",
        "severity": "HIGH",
        "fix_version": "14.2.32",
        "description": (
            "Next.js is vulnerable to SSRF via header injection, allowing "
            "attackers to access internal services and cloud metadata endpoints."
        ),
        "references": [],
    },
    "CVE-2024-34351": {
        "id": "CVE-2024-34351",
        "short": "34351",
        "title": "SSRF via Server Actions Host Header",
        "type": "SSRF",
        "severity": "HIGH",
        "fix_version": "14.1.1",
        "description": (
            "Next.js Server Actions use the attacker-controlled Host header to "
            "build absolute URLs for internal redirect requests. A malicious "
            "server can pass the HEAD verification (Content-Type: text/x-component) "
            "and redirect the GET request to internal services like cloud metadata."
        ),
        "references": [
            "https://github.com/vercel/next.js/security/advisories/GHSA-fr5h-rqp8-mj6g",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-34351",
        ],
    },
    "CVE-2024-51479": {
        "id": "CVE-2024-51479",
        "short": "51479",
        "title": "Authentication Bypass",
        "type": "Auth Bypass",
        "severity": "HIGH",
        "fix_version": "14.2.15",
        "description": "Authentication bypass vulnerability in Next.js.",
        "references": [],
    },
    "CVE-2025-55183": {
        "id": "CVE-2025-55183",
        "short": "55183",
        "title": "Source Code Exposure via RSC Server Functions",
        "type": "Information Disclosure",
        "severity": "MEDIUM",  # CVSS 5.3 per NVD — corrected from HIGH
        "fix_version": "14.2.35",
        "description": (
            "RSC Server Functions do not override toString(), causing them to "
            "return their full source code when stringified. A crafted HTTP "
            "request can coerce a Server Function to leak API keys, business "
            "logic, or secrets embedded in the source. CVSS 5.3 (Medium)."
        ),
        "references": [
            "https://github.com/vercel/next.js/security/advisories",
        ],
    },
    "CVE-2025-55184": {
        "id": "CVE-2025-55184",
        "short": "55184",
        "title": "Denial of Service via Infinite Promise Recursion (RSC)",
        "type": "DoS",
        "severity": "HIGH",  # CVSS 7.5 per NVD — corrected from MEDIUM
        "fix_version": "14.2.35",
        "description": (
            "An attacker can send a malformed RSC request to an App Router endpoint "
            "that triggers an infinite promise recursion loop, hanging the server "
            "process and causing DoS. CVSS 7.5 (High). "
            "WARNING: The initial patch for this CVE was INCOMPLETE — "
            "see CVE-2025-67779 for the full fix (React 19.0.3/19.1.4/19.2.3)."
        ),
        "references": [
            "https://github.com/vercel/next.js/security/advisories",
        ],
    },
    "CVE-2025-67779": {
        "id": "CVE-2025-67779",
        "short": "67779",
        "title": "DoS Incomplete Fix — Infinite Promise Loop (RSC Follow-up)",
        "type": "DoS",
        "severity": "HIGH",  # CVSS 7.5
        "fix_version": "15.3.0",  # Next.js bundling React 19.0.3+
        "description": (
            "CVE-2025-55184 was initially patched with an incomplete fix. "
            "This follow-up CVE covers the remaining attack surface: unsafe "
            "deserialization of RSC payloads in react-server-dom-* packages "
            "(< 19.0.3 / 19.1.4 / 19.2.3) still triggers infinite promise "
            "recursion. Applications using React 19.0.2, 19.1.3, or 19.2.2 "
            "bundled with Next.js remain vulnerable. CVSS 7.5 (High)."
        ),
        "references": [
            "https://github.com/facebook/react/security/advisories",
            "https://github.com/vercel/next.js/security/advisories",
        ],
    },
    "CVE-2025-66478": {
        "id": "CVE-2025-66478",
        "short": "66478",
        "title": "RCE via RSC Flight Protocol Deserialization",
        "type": "RCE",
        "severity": "CRITICAL",
        "fix_version": "15.0.5",
        "description": (
            "React2Shell — Remote Code Execution via unsafe deserialization of "
            "the RSC Flight Protocol. Crafted __proto__ payloads sent to Server "
            "Action endpoints can hijack the requireModule resolver, leading to "
            "arbitrary shell command execution via Node.js child_process. "
            "CVSS 10.0. Also tracked as CVE-2025-55182."
        ),
        "references": [
            "https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182",
        ],
    },
    "CVE-2024-46982": {
        "id": "CVE-2024-46982",
        "short": "46982",
        "title": "Cache Poisoning / Stored XSS via x-now-route-matches",
        "type": "Cache Poisoning / XSS",
        "severity": "HIGH",
        "fix_version": "14.2.10",
        "description": (
            "Vulnerability in Next.js pages router allowing cache poisoning. "
            "An attacker can exploit fallback caching logic using x-now-route-matches "
            "header to cache malicious responses (like XSS payloads in User-Agent) "
            "which are then served to other users. CVSS 7.5."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-46982",
        ],
    },
    "CVE-2024-56332": {
        "id": "CVE-2024-56332",
        "short": "56332",
        "title": "Authorization Bypass via Pathname Middleware",
        "type": "Auth Bypass",
        "severity": "HIGH",
        "fix_version": "14.2.25", # Assuming same as 29927 or general recent patch
        "description": (
            "If a Next.js application performs authorization in middleware based on "
            "the request pathname, it may be possible to bypass this authorization "
            "using pathname manipulation techniques (e.g., encoding, traversal)."
        ),
        "references": [
            "https://github.com/vercel/next.js/security/advisories/GHSA-7gfc-8cq8-jh5f",
        ],
    },
    "CVE-2025-48068": {
        "id": "CVE-2025-48068",
        "short": "48068",
        "title": "Source Code Exposure via Dev Server",
        "type": "Info Disclosure",
        "severity": "LOW",
        "fix_version": "15.2.2",
        "description": (
            "Next.js dev server does not properly verify request origins, allowing "
            "source code exposure if the dev server is exposed. Attackers can fetch "
            "internal code chunks by supplying a spoofed Origin and specific Accept headers."
        ),
        "references": [
            "https://github.com/vercel/next.js/security/advisories/GHSA-3h52-269p-cp9r",
        ],
    },
    "CVE-2024-34350": {
        "id": "CVE-2024-34350",
        "short": "34350",
        "title": "HTTP Request Smuggling / Response Queue Poisoning",
        "type": "Request Smuggling",
        "severity": "HIGH",
        "fix_version": "13.5.1",
        "description": (
            "Under certain configurations utilizing rewrites, it may be possible to trigger "
            "HTTP Request Smuggling / Response Queue Poisoning in Next.js applications."
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-34350",
        ],
    },
    "CVE-2025-59471": {
        "id": "CVE-2025-59471",
        "short": "59471",
        "title": "Image Optimizer OOM Denial of Service",
        "type": "DoS",
        "severity": "MEDIUM",
        "fix_version": "15.5.10",
        "description": (
            "Out of Memory (OOM) denial of service vulnerability in Next.js Image Optimization API "
            "allowing unauthenticated attackers to crash the service via crafted dynamic size parameters."
        ),
        "references": [
            "https://github.com/vercel/next.js/security/advisories/GHSA-958m-fp9f-f9r5",
        ],
    },
    "CVE-2026-23870": {
        "id": "CVE-2026-23870",
        "short": "23870",
        "title": "DoS via RSC Deserialization",
        "type": "DoS",
        "severity": "HIGH",
        "fix_version": "15.5.16",
        "description": (
            "Denial of Service (DoS) in App Router Server Actions when handling deserialization of "
            "malformed React Server Component (RSC) flight data, triggering unhandled promise rejections."
        ),
        "references": [
            "https://github.com/vercel/next.js/security/advisories",
        ],
    },
    "CVE-2026-44575": {
        "id": "CVE-2026-44575",
        "short": "44575",
        "title": "Middleware Bypass via Segment-Prefetch Routes",
        "type": "Auth Bypass",
        "severity": "HIGH",
        "fix_version": "15.5.16",
        "description": (
            "Next.js App Router generates route variants (.rsc, .prefetch.rsc) for "
            "segment prefetching whose middleware path-matchers differ from the canonical "
            "route. Middleware is NOT triggered for these variants, granting unauthenticated "
            "access to protected pages in Next.js 15.2.0–15.5.15."
        ),
        "references": [
            "https://github.com/vercel/next.js/security/advisories",
        ],
    },
    "CVE-2026-23864": {
        "id": "CVE-2026-23864",
        "short": "23864",
        "title": "DoS via RSC Memory Exhaustion (FormData $K Token Amplification)",
        "type": "DoS",
        "severity": "HIGH",
        "fix_version": "15.5.10",
        "description": (
            "The React Flight protocol decoder in Next.js 15.5.0–15.5.9 allocates memory "
            "for every '$K<id>:FormData' token in a multipart FormData body posted to a "
            "Server Action endpoint. A crafted request with thousands of such tokens causes "
            "unbounded memory growth (OOM), crashing the Node.js process. CVSS 7.5."
        ),
        "references": [
            "https://github.com/vercel/next.js/security/advisories",
        ],
    },
    "GHSA-mg66-mrh9-m8jx": {
        "id": "GHSA-mg66-mrh9-m8jx",
        "short": "mg66",
        "title": "DoS via PPR/Cache Components Connection Deadlock",
        "type": "DoS",
        "severity": "HIGH",
        "fix_version": "15.5.16",
        "description": (
            "When Partial Pre-Rendering (PPR) or cacheComponents is enabled, a POST request "
            "carrying the 'Next-Resume: 1' header deadlocks the internal connection pool. "
            "Concurrent requests pile up until the process exhausts file handles, causing a "
            "Denial of Service. Affects Next.js < 15.5.16 with PPR enabled."
        ),
        "references": [
            "https://github.com/advisories/GHSA-mg66-mrh9-m8jx",
        ],
    },
    "CVE-2026-45109": {
        "id": "CVE-2026-45109",
        "short": "45109",
        "title": "Middleware Bypass via Turbopack (Incomplete Fix Follow-up)",
        "type": "Auth Bypass",
        "severity": "HIGH",
        "fix_version": "15.5.18",
        "description": (
            "CVE-2026-44575 was only partially fixed in 15.5.16. The Turbopack bundler "
            "code path still allows .rsc and .prefetch.rsc route variants to bypass "
            "middleware in Next.js 15.5.16–15.5.17 when Turbopack is enabled, granting "
            "unauthenticated access to protected routes."
        ),
        "references": [
            "https://github.com/vercel/next.js/security/advisories",
        ],
    },
}



def check_vuln_status(detected_version: str, cve_id: str) -> str:
    """Check if detected version is vulnerable to a specific CVE."""
    cve = CVE_DATABASE.get(cve_id)
    if not cve:
        return "UNKNOWN"

    fix = cve["fix_version"]
    try:
        detected_parts = [int(x) for x in detected_version.split(".")]
        fix_parts = [int(x) for x in fix.split(".")]

        # Pad to equal length
        max_len = max(len(detected_parts), len(fix_parts))
        detected_parts.extend([0] * (max_len - len(detected_parts)))
        fix_parts.extend([0] * (max_len - len(fix_parts)))

        if detected_parts < fix_parts:
            return "VULNERABLE"
        elif detected_parts == fix_parts:
            return "PATCHED (at fix version)"
        else:
            return "PATCHED"
    except (ValueError, AttributeError):
        return "UNKNOWN"


# ─── Scan Configuration ─────────────────────────────────────────────────────

@dataclass
class ScanConfig:
    """Global scan configuration passed to all modules."""
    target: str
    timeout: int = 10
    threads: int = 10
    verbosity: int = 0  # 0=normal, 1=verbose, 2=extra verbose
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    proxy: Optional[str] = None
    verify_ssl: bool = True
    output_file: Optional[str] = None
    output_dir: str = "reports"
    cve_list: list = field(default_factory=list)
    scan_all: bool = False
    # Extra context populated by fingerprint module
    discovered_build_id: Optional[str] = None
    discovered_action_ids: list = field(default_factory=list)
    # Browser exploit integration (AnonKryptiQuz chaining)
    browser_exploit: bool = False
    waf_bypass: bool = False

    @property
    def proxies(self) -> Optional[dict]:
        if self.proxy:
            return {"http": self.proxy, "https": self.proxy}
        return None

    def save_response(self, filename: str, response: requests.Response) -> str:
        """Save full HTTP response (status, headers, and body) to output_dir."""
        import os
        os.makedirs(self.output_dir, exist_ok=True)
        filepath = os.path.join(self.output_dir, filename)
        try:
            with open(filepath, "w", encoding="utf-8", errors="ignore") as f:
                f.write(f"HTTP/1.1 {response.status_code} {response.reason}\n")
                for k, v in response.headers.items():
                    f.write(f"{k}: {v}\n")
                f.write("\n")
                f.write(response.text)
            return filepath
        except Exception:
            return ""

    def create_session(self) -> requests.Session:
        """Create a configured requests.Session."""
        session = requests.Session()
        session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        })
        if self.proxies:
            session.proxies.update(self.proxies)
        session.verify = self.verify_ssl
        return session
