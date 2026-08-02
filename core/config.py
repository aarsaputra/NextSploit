#!/usr/bin/env python3
"""
NextSploit — Core Configuration & Shared Resources
"""

from dataclasses import dataclass, field
from typing import Optional
import threading
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
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
        "alias_of": "CVE-2025-59472 (sibling CVE assigned to same Image Optimizer OOM advisory)",
        "description": (
            "Out of Memory (OOM) denial of service vulnerability in Next.js Image Optimization API "
            "allowing unauthenticated attackers to crash the service via crafted dynamic size parameters. "
            "Covers sibling advisory CVE-2025-59472."
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
        "cve_alias": "CVE-2026-44579",
        "short": "mg66",
        "title": "DoS via PPR/Cache Components Connection Deadlock",
        "type": "DoS",
        "severity": "HIGH",
        "ranges": [
            {"min_version": "15.0.0", "fix_version": "15.5.16", "branch": "15.x"},
            {"min_version": "16.0.0", "fix_version": "16.2.5",  "branch": "16.x"},
        ],
        "description": (
            "When Partial Pre-Rendering (PPR) or cacheComponents is enabled, a POST request "
            "carrying the 'Next-Resume: 1' header deadlocks the internal connection pool. "
            "Concurrent requests pile up until the process exhausts file handles, causing a "
            "Denial of Service. Also known as CVE-2026-44579."
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
        "ranges": [
            {"min_version": "15.5.16", "fix_version": "15.5.18", "branch": "15.x"},
        ],
        "description": (
            "CVE-2026-44575 was only partially fixed in 15.5.16. The Turbopack bundler "
            "code path still allows .rsc and .prefetch.rsc route variants to bypass "
            "middleware in Next.js 15.5.16–15.5.17 when Turbopack is enabled."
        ),
        "references": [
            "https://github.com/vercel/next.js/security/advisories",
        ],
    },
    # ── Batch #1 — Mei 2026 (fix: v15.5.16 / v16.2.5) ──────────────────────
    "CVE-2026-44573": {
        "id": "CVE-2026-44573",
        "short": "44573",
        "title": "Pages Router i18n Data-Route Middleware Bypass",
        "type": "Auth Bypass",
        "severity": "HIGH",
        "ranges": [
            {"min_version": "12.2.0", "fix_version": "15.5.16", "branch": "15.x"},
            {"min_version": "16.0.0", "fix_version": "16.2.5",  "branch": "16.x"},
        ],
        "description": (
            "Requests without locale prefix to /_next/data/<buildId>/<page>.json skip "
            "middleware in Pages Router apps with i18n enabled, allowing unauthorized "
            "access to protected page data. GHSA-36qx-fr4f-26g5."
        ),
        "references": ["https://github.com/advisories/GHSA-36qx-fr4f-26g5"],
    },
    "CVE-2026-44574": {
        "id": "CVE-2026-44574",
        "short": "44574",
        "title": "Dynamic-Route & Middleware Pattern Mismatch",
        "type": "Auth Bypass",
        "severity": "HIGH",
        "ranges": [
            {"min_version": "13.0.0", "fix_version": "15.5.16", "branch": "15.x"},
            {"min_version": "16.0.0", "fix_version": "16.2.5",  "branch": "16.x"},
        ],
        "description": (
            "Middleware path-matcher does not correctly match dynamic route segments, "
            "allowing crafted URLs to bypass middleware authentication. GHSA-492v-c6pp-mqqv."
        ),
        "references": ["https://github.com/advisories/GHSA-492v-c6pp-mqqv"],
    },
    "CVE-2026-44578": {
        "id": "CVE-2026-44578",
        "short": "44578",
        "title": "WebSocket Upgrade SSRF (Self-Hosted)",
        "type": "SSRF",
        "severity": "HIGH",
        "single_branch_reason": "WebSocket upgrade routes introduced in 16.x stable, not present in 15.x",
        "ranges": [
            # 16.x ONLY — WebSocket upgrade routes not in 15.x stable
            {"min_version": "16.0.0", "fix_version": "16.2.5", "branch": "16.x"},
        ],
        "description": (
            "Self-hosted Next.js 16.x applications expose WebSocket upgrade routes that "
            "reflect the Host header in outbound connections, enabling SSRF to internal "
            "services. Not present in Next.js 15.x. GHSA-c4j6-fc7j-m34r."
        ),
        "references": ["https://github.com/advisories/GHSA-c4j6-fc7j-m34r"],
    },
    "CVE-2026-44577": {
        "id": "CVE-2026-44577",
        "short": "44577",
        "title": "Image Optimizer Decompression Bomb (Self-Hosted)",
        "type": "DoS",
        "severity": "MEDIUM",
        "ranges": [
            {"min_version": "13.0.0", "fix_version": "15.5.16", "branch": "15.x"},
            {"min_version": "16.0.0", "fix_version": "16.2.5",  "branch": "16.x"},
        ],
        "description": (
            "The /_next/image endpoint in self-hosted deployments is vulnerable to "
            "decompression bomb attacks via crafted image inputs, causing OOM crashes. "
            "GHSA-h64f-5h5j-jqjh."
        ),
        "references": ["https://github.com/advisories/GHSA-h64f-5h5j-jqjh"],
    },
    "CVE-2026-44576": {
        "id": "CVE-2026-44576",
        "short": "44576",
        "title": "RSC & HTML Response Cache Confusion",
        "type": "Cache Poisoning",
        "severity": "MEDIUM",
        "ranges": [
            {"min_version": "13.0.0", "fix_version": "15.5.16", "branch": "15.x"},
            {"min_version": "16.0.0", "fix_version": "16.2.5",  "branch": "16.x"},
        ],
        "description": (
            "RSC and HTML responses can be confused in the cache under specific request "
            "patterns, causing users to receive incorrect cached content. GHSA-wfc6-r584-vfw7."
        ),
        "references": ["https://github.com/advisories/GHSA-wfc6-r584-vfw7"],
    },
    "CVE-2026-44580": {
        "id": "CVE-2026-44580",
        "short": "44580",
        "title": "next/script beforeInteractive XSS",
        "type": "XSS",
        "severity": "MEDIUM",
        "ranges": [
            {"min_version": "13.0.0", "fix_version": "15.5.16", "branch": "15.x"},
            {"min_version": "16.0.0", "fix_version": "16.2.5",  "branch": "16.x"},
        ],
        "description": (
            "The beforeInteractive strategy in next/script does not correctly sanitize "
            "script src attributes, allowing reflected XSS in certain configurations. "
            "GHSA-gx5p-jg67-6x7h."
        ),
        "references": ["https://github.com/advisories/GHSA-gx5p-jg67-6x7h"],
    },
    "CVE-2026-44581": {
        "id": "CVE-2026-44581",
        "short": "44581",
        "title": "CSP Nonce Parsing Edge Case",
        "type": "Info Disclosure",
        "severity": "MEDIUM",
        "ranges": [
            {"min_version": "13.0.0", "fix_version": "15.5.16", "branch": "15.x"},
            {"min_version": "16.0.0", "fix_version": "16.2.5",  "branch": "16.x"},
        ],
        "description": (
            "A CSP nonce parsing edge case allows the nonce to leak in predictable "
            "scenarios, weakening Content Security Policy protections. GHSA-ffhc-5mcf-pf4q."
        ),
        "references": ["https://github.com/advisories/GHSA-ffhc-5mcf-pf4q"],
    },
    "CVE-2026-44582": {
        "id": "CVE-2026-44582",
        "short": "44582",
        "title": "Weak _rsc Cache-Busting Hash",
        "type": "Info Disclosure",
        "severity": "LOW",
        "ranges": [
            {"min_version": "13.0.0", "fix_version": "15.5.16", "branch": "15.x"},
            {"min_version": "16.0.0", "fix_version": "16.2.5",  "branch": "16.x"},
        ],
        "description": (
            "The _rsc query parameter hash is predictable, allowing attackers to bypass "
            "cache-busting and serve stale RSC payloads. GHSA-vfv6-92ff-j949."
        ),
        "references": ["https://github.com/advisories/GHSA-vfv6-92ff-j949"],
    },
    "CVE-2026-44572": {
        "id": "CVE-2026-44572",
        "short": "44572",
        "title": "x-nextjs-data Redirect Cache Poisoning",
        "type": "Cache Poisoning",
        "severity": "LOW",
        "ranges": [
            {"min_version": "13.0.0", "fix_version": "15.5.16", "branch": "15.x"},
            {"min_version": "16.0.0", "fix_version": "16.2.5",  "branch": "16.x"},
        ],
        "description": (
            "The x-nextjs-data header can be abused to cache redirect responses, "
            "causing cache poisoning via malicious redirect entries. GHSA-3g8h-86w9-wvmq."
        ),
        "references": ["https://github.com/advisories/GHSA-3g8h-86w9-wvmq"],
    },
    # ── Batch #2 — Juli 2026 (fix: v15.5.21 / v16.2.11) ────────────────────
    "CVE-2026-64641": {
        "id": "CVE-2026-64641",
        "short": "64641",
        "title": "DoS App Router via Server Actions CPU Exhaustion",
        "type": "DoS",
        "severity": "HIGH",
        "ranges": [
            {"min_version": "13.0.0", "fix_version": "15.5.21", "branch": "15.x"},
            {"min_version": "16.0.0", "fix_version": "16.2.11", "branch": "16.x"},
        ],
        "description": (
            "Crafted requests targeting App Router applications with at least one "
            "Server Action cause excessive CPU usage, blocking processing of further "
            "requests (Denial of Service). GHSA-m99w-x7hq-7vfj."
        ),
        "references": ["https://github.com/advisories/GHSA-m99w-x7hq-7vfj"],
    },
    "CVE-2026-64642": {
        "id": "CVE-2026-64642",
        "short": "64642",
        "title": "Middleware Bypass — App Router + Turbopack + Single-Locale i18n",
        "type": "Auth Bypass",
        "severity": "HIGH",
        "single_branch_reason": "App Router + Turbopack single-locale i18n routing table issue associated with 16.x builds",
        "ranges": [
            {"min_version": "16.0.0", "fix_version": "16.2.11", "branch": "16.x"},
        ],
        "description": (
            "App Router applications built with Turbopack and a single entry in "
            "config.i18n.locales are vulnerable to middleware/proxy bypass, granting "
            "unauthenticated access to protected routes. GHSA-6gpp-xcg3-4w24."
        ),
        "references": ["https://github.com/advisories/GHSA-6gpp-xcg3-4w24"],
    },
    "CVE-2026-64645": {
        "id": "CVE-2026-64645",
        "short": "64645",
        "title": "SSRF via rewrites()/redirects() Hostname Injection",
        "type": "SSRF",
        "severity": "HIGH",
        "ranges": [
            {"min_version": "12.0.0", "fix_version": "15.5.21", "branch": "15.x"},
            {"min_version": "16.0.0", "fix_version": "16.2.11", "branch": "16.x"},
        ],
        "description": (
            "A rewrites() or redirects() rule that builds its external destination "
            "hostname from request-controlled input can be pointed at an arbitrary "
            "hostname, enabling SSRF to internal services and cloud metadata endpoints."
        ),
        "references": ["https://nextjs.org/blog/july-2026-security-release"],
    },
    "CVE-2026-64649": {
        "id": "CVE-2026-64649",
        "short": "64649",
        "title": "SSRF Server Actions via Host Header (Custom Node.js Server)",
        "type": "SSRF",
        "severity": "HIGH",
        "ranges": [
            {"min_version": "14.1.1", "fix_version": "15.5.21", "branch": "15.x"},
            {"min_version": "16.0.0", "fix_version": "16.2.11", "branch": "16.x"},
        ],
        "description": (
            "When a Server Action forwards or redirects a request on a custom Node.js "
            "server, an attacker can manipulate the Host header to cause the server to "
            "send that outbound request to a malicious host (SSRF). GHSA-89xv-2m56-2m9x."
        ),
        "references": ["https://github.com/advisories/GHSA-89xv-2m56-2m9x"],
    },
    "CVE-2026-64644": {
        "id": "CVE-2026-64644",
        "short": "64644",
        "title": "DoS Image Optimization API via SVG",
        "type": "DoS",
        "severity": "MEDIUM",
        "ranges": [
            {"min_version": "15.5.0", "fix_version": "15.5.21", "branch": "15.x"},
            {"min_version": "16.0.0", "fix_version": "16.2.11", "branch": "16.x"},
        ],
        "description": (
            "Crafted SVG payloads sent to the /_next/image endpoint cause CPU "
            "exhaustion, blocking image optimization requests (Denial of Service). GHSA-q8wf-6r8g-63ch."
        ),
        "references": ["https://github.com/advisories/GHSA-q8wf-6r8g-63ch"],
    },
    "CVE-2026-64646": {
        "id": "CVE-2026-64646",
        "short": "64646",
        "title": "Unbounded Server Action Payload — Edge Runtime Memory Exhaustion",
        "type": "DoS",
        "severity": "MEDIUM",
        "ranges": [
            {"min_version": "13.0.0", "fix_version": "15.5.21", "branch": "15.x"},
            {"min_version": "16.0.0", "fix_version": "16.2.11", "branch": "16.x"},
        ],
        "description": (
            "Server Action endpoints running in the Edge runtime do not enforce "
            "payload size limits, allowing memory exhaustion via large request bodies. GHSA-4c39-4ccg-62r3."
        ),
        "references": ["https://github.com/advisories/GHSA-4c39-4ccg-62r3"],
    },
    "CVE-2026-64643": {
        "id": "CVE-2026-64643",
        "short": "64643",
        "title": "Server Action / use cache Endpoint ID Enumerable Without Auth",
        "type": "Info Disclosure",
        "severity": "MEDIUM",
        "ranges": [
            {"min_version": "13.0.0", "fix_version": "15.5.21", "branch": "15.x"},
            {"min_version": "16.0.0", "fix_version": "16.2.11", "branch": "16.x"},
        ],
        "description": (
            "Server Action and 'use cache' endpoint IDs are exposed in error "
            "responses and can be enumerated without authentication, providing "
            "a significant reconnaissance vector. GHSA-955p-x3mx-jcvp."
        ),
        "references": ["https://github.com/advisories/GHSA-955p-x3mx-jcvp"],
    },
    "CVE-2026-64648": {
        "id": "CVE-2026-64648",
        "short": "64648",
        "title": "Cache Confusion — fetch() Response Body Mismatch",
        "type": "Cache Poisoning",
        "severity": "MEDIUM",
        "ranges": [
            {"min_version": "13.0.0", "fix_version": "15.5.21", "branch": "15.x"},
            {"min_version": "16.0.0", "fix_version": "16.2.11", "branch": "16.x"},
        ],
        "description": (
            "The fetch() cache in Next.js can serve a response body intended for "
            "one request to a different request under certain conditions, causing "
            "cache confusion and potential data leakage between users. GHSA-68g3-v927-f742."
        ),
        "references": ["https://github.com/advisories/GHSA-68g3-v927-f742"],
    },
    "CVE-2026-64647": {
        "id": "CVE-2026-64647",
        "short": "64647",
        "title": "Cache Confusion — Invalid UTF-8 Request Body Variant",
        "type": "Cache Poisoning",
        "severity": "MEDIUM",
        "ranges": [
            {"min_version": "13.0.0", "fix_version": "15.5.21", "branch": "15.x"},
            {"min_version": "16.0.0", "fix_version": "16.2.11", "branch": "16.x"},
        ],
        "description": (
            "Variant of CVE-2026-64648 triggered specifically by request bodies "
            "containing invalid UTF-8 byte sequences, causing cache confusion "
            "and potential response body leakage. GHSA-4633-3j49-mh5q."
        ),
        "references": ["https://github.com/advisories/GHSA-4633-3j49-mh5q"],
    },
}


def _parse_ver(ver: str) -> list:
    """Parse a semver string into a list of ints. Returns [] on failure."""
    try:
        return [int(x) for x in ver.split(".")]
    except (ValueError, AttributeError):
        return []


def _ver_in_range(detected: list, min_v: list, fix_v: list) -> bool:
    """Return True if detected >= min_v and detected < fix_v."""
    # Pad to equal length
    n = max(len(detected), len(min_v), len(fix_v))
    d = detected + [0] * (n - len(detected))
    lo = min_v  + [0] * (n - len(min_v))
    hi = fix_v  + [0] * (n - len(fix_v))
    return lo <= d < hi


def check_vuln_status(detected_version: str, cve_id: str) -> str:
    """
    Check whether detected_version is vulnerable to cve_id.

    Supports two CVE_DATABASE formats:
      1. Multi-range (new): entry has 'ranges' list with min_version/fix_version per branch.
      2. Legacy (old):      entry has single 'fix_version' string.

    Returns: 'VULNERABLE' | 'PATCHED' | 'PATCHED (at fix version)' | 'UNKNOWN'
    """
    cve = CVE_DATABASE.get(cve_id)
    if not cve:
        return "UNKNOWN"

    detected = _parse_ver(detected_version)
    if not detected:
        return "UNKNOWN"

    # ── Multi-range format ──────────────────────────────────────────────────
    if "ranges" in cve:
        for rng in cve["ranges"]:
            min_v = _parse_ver(rng.get("min_version", "0.0.0"))
            fix_v = _parse_ver(rng["fix_version"])
            if _ver_in_range(detected, min_v, fix_v):
                return "VULNERABLE"
            # Check if exactly at fix boundary
            n = max(len(detected), len(fix_v))
            d = detected + [0] * (n - len(detected))
            h = fix_v   + [0] * (n - len(fix_v))
            if d == h:
                return "PATCHED (at fix version)"
        return "PATCHED"

    # ── Legacy single fix_version format (backward-compat) ──────────────────
    fix = cve.get("fix_version", "")
    fix_v = _parse_ver(fix)
    if not fix_v:
        return "UNKNOWN"
    n = max(len(detected), len(fix_v))
    d = detected + [0] * (n - len(detected))
    h = fix_v   + [0] * (n - len(fix_v))
    if d < h:
        return "VULNERABLE"
    elif d == h:
        return "PATCHED (at fix version)"
    return "PATCHED"


# ─── Rate Limiter ───────────────────────────────────────────────────────────────────────

class RateLimiter:
    """
    Token bucket rate limiter.
    Call `acquire()` before each HTTP request to honour --rate-limit.
    Thread-safe.
    """

    def __init__(self, max_per_second: float):
        self._lock = threading.Lock()
        self._max = max_per_second
        self._tokens = max_per_second
        self._last = time.monotonic()

    def acquire(self) -> None:
        if self._max <= 0:
            return  # no limit
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(self._max, self._tokens + elapsed * self._max)
            if self._tokens < 1:
                sleep_time = (1 - self._tokens) / self._max
                time.sleep(sleep_time)
                self._tokens = 0
            else:
                self._tokens -= 1


# ─── Scan Configuration ────────────────────────────────────────────────────────────────────

@dataclass
class ScanConfig:
    """Global scan configuration passed to all modules."""
    target: str
    timeout: int = 10
    threads: int = 10
    verbosity: int = 0            # 0=normal, 1=verbose, 2=extra verbose
    user_agent: str = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    )
    proxy: Optional[str] = None
    verify_ssl: bool = True
    output_file: Optional[str] = None
    output_dir: str = "reports"
    cve_list: list = field(default_factory=list)
    scan_all: bool = False

    # — Fingerprint context (populated by fingerprint module) —
    discovered_build_id: Optional[str] = None
    discovered_action_ids: list = field(default_factory=list)
    discovered_js_chunks: list = field(default_factory=list)
    discovered_css_chunks: list = field(default_factory=list)
    detected_router_type: Optional[str] = None  # "app" | "pages" | None

    # — Browser exploit integration (AnonKryptiQuz chaining) —
    browser_exploit: bool = False
    waf_bypass: bool = False

    # — Active-mode opt-in (modules that touch external hosts or shared cache) —
    confirm_active: bool = False  # --confirm-active flag

    # — Rate-limiting —
    delay: float = 0.0          # seconds between requests (--delay)
    rate_limit: int = 0         # max requests/second (--rate-limit); 0 = no limit

    # — Private: initialized in __post_init__ —
    _counter_lock: object = field(default=None, init=False, repr=False, compare=False)
    _blocked_requests: int = field(default=0, init=False, repr=False, compare=False)
    _total_requests: int = field(default=0, init=False, repr=False, compare=False)
    _rate_limiter: object = field(default=None, init=False, repr=False, compare=False)
    _version_state: object = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._counter_lock = threading.Lock()
        self._blocked_requests = 0
        self._total_requests = 0
        self._rate_limiter = RateLimiter(self.rate_limit)
        from core.version_state import VersionState
        self._version_state = VersionState()

    # ─── Version State ─────────────────────────────────────────────────────────────

    @property
    def version_state(self):
        return self._version_state

    def report_version(self, value: str, confidence: float, source: str) -> None:
        """
        Report a discovered Next.js version signal from any module.
        Thread-safe. The orchestrator reads config.version_state.best() at the
        end of the scan to determine the authoritative version.

        Args:
            value:      Version string, e.g. "14.2.35"
            confidence: 0.0 – 1.0
            source:     "buildid" | "header" | "chunk_js" | "error_leak" | "module_infer"
        """
        self._version_state.add(value, confidence, source)

    # ─── Request Counters (thread-safe) ────────────────────────────────────────────────

    def record_request(self, status_code: int) -> None:
        """
        Record the outcome of one HTTP request.  Call this after every
        requests.get/post inside a module so the orchestrator can compute
        noise_ratio and determine if the result is INCONCLUSIVE.
        Thread-safe.
        """
        with self._counter_lock:
            self._total_requests += 1
            if status_code in (403, 429, 503):
                self._blocked_requests += 1

    def noise_ratio(self) -> float:
        """Fraction of blocked responses (0.0 – 1.0). Thread-safe."""
        with self._counter_lock:
            if self._total_requests == 0:
                return 0.0
            return self._blocked_requests / self._total_requests

    def total_request_count(self) -> int:
        """Total requests made in the current module window. Thread-safe."""
        with self._counter_lock:
            return self._total_requests

    def reset_request_counters(self) -> None:
        """Reset per-module counters.  Called by the orchestrator between modules."""
        with self._counter_lock:
            self._blocked_requests = 0
            self._total_requests = 0

    # ─── Precondition Helpers ──────────────────────────────────────────────────────────

    def has_active_server_actions(self) -> bool:
        """
        True if the fingerprint phase discovered at least one Server Action ID.
        Modules that depend on Server Actions should return NOT_APPLICABLE when
        this is False.
        """
        return bool(self.discovered_action_ids)

    def has_discovered_assets(self) -> bool:
        """
        True if at least one JS or CSS chunk was discovered during fingerprinting.
        Modules that inspect static bundle contents should return NOT_APPLICABLE
        when this is False.
        """
        return bool(self.discovered_js_chunks) or bool(self.discovered_css_chunks)

    def has_app_router(self) -> bool:
        """
        True if the fingerprint phase identified the target as an App Router app.
        Returns True also when detected_router_type is None (unknown) to avoid
        false NOT_APPLICABLE on targets that simply hide their router type.
        Callers may combine this with has_active_server_actions() for stricter checks.
        """
        if self.detected_router_type is None:
            return True   # uncertain — do not skip the module
        return self.detected_router_type == "app"

    # ─── Rate-Limiting Helper ───────────────────────────────────────────────────────────

    def throttle(self) -> None:
        """
        Call before each outbound HTTP request to honour --delay and
        --rate-limit settings simultaneously.
        """
        if self.delay > 0:
            time.sleep(self.delay)
        self._rate_limiter.acquire()

    # ─── Proxies ────────────────────────────────────────────────────────────────────────────

    @property
    def proxies(self) -> Optional[dict]:
        if self.proxy:
            return {"http": self.proxy, "https": self.proxy}
        return None

    # ─── Evidence Saving ────────────────────────────────────────────────────────────────────

    def save_response(self, filename: str, response: requests.Response) -> str:
        """Save full HTTP response (status, headers, body) to output_dir."""
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

    # ─── Session Factory ────────────────────────────────────────────────────────────────────

    def create_session(self) -> requests.Session:
        """
        Create a configured NextSploitSession (subclass of requests.Session) with:
        - Custom User-Agent and standard Accept headers
        - Proxy passthrough (--proxy)
        - Automatic retry with exponential backoff on 429/503
          (up to 3 retries, respects Retry-After header)
        - Automated rate limiting, delay, and blocked request tracking.
        """
        session = NextSploitSession(self)
        session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        })
        if self.proxies:
            session.proxies.update(self.proxies)
        session.verify = self.verify_ssl

        # Retry adapter: back-off on transient errors and rate-limit responses
        retry_strategy = Retry(
            total=3,
            backoff_factor=1.5,              # waits: 1.5s, 3s, 4.5s
            status_forcelist=[429, 503],     # retry these status codes
            respect_retry_after_header=True,  # honour Retry-After
            allowed_methods=["GET", "POST", "HEAD"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://",  adapter)

        return session


class NextSploitSession(requests.Session):
    """
    Subclass of requests.Session that intercepts all HTTP requests to
    automatically apply rate-limiting/delay and record stats for WAF noise analysis.
    """

    def __init__(self, config: ScanConfig):
        super().__init__()
        self.config = config

    def request(self, method, url, *args, **kwargs):
        self.config.throttle()
        try:
            resp = super().request(method, url, *args, **kwargs)
            self.config.record_request(resp.status_code)
            return resp
        except Exception:
            # Treat network exceptions (timeouts/connection drop) as potential WAF block
            self.config.record_request(503)
            raise

