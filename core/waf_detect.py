#!/usr/bin/env python3
"""
NextSploit — WAF/Challenge Page Detection Helpers (Addendum #38)

Classifies blocked HTTP responses into actionable categories so that
the scan summary can tell the operator HOW to handle the noise —
not just that there was noise.
"""

# ─── Cloudflare Challenge Markers ───────────────────────────────────────────
CLOUDFLARE_CHALLENGE_MARKERS = [
    "Checking your browser before accessing",
    "cf-browser-verification",
    "cf_chl_",
    "Just a moment...",
    "__cf_chl_rt_tk",
    "challenge-platform",
    "cf_clearance",
]

# ─── Generic WAF Block Markers ───────────────────────────────────────────────
GENERIC_WAF_MARKERS = [
    "Request blocked",
    "Access Denied",
    "The requested URL was rejected",
    "Forbidden by",
    "Web Application Firewall",
    "Incapsula incident",
    "mod_security",
]

# ─── Rate-Limit Markers ──────────────────────────────────────────────────────
RATE_LIMIT_MARKERS = [
    "Too Many Requests",
    "rate limit exceeded",
    "slow down",
]


def classify_blocked_response(response) -> str:
    """
    Classify a blocked HTTP response into one of four categories:
      'challenge'      → Cloudflare JS challenge (needs headless browser)
      'rate_limit'     → HTTP 429 or explicit rate-limit body
      'waf_block'      → Generic WAF hard-block
      'generic_block'  → 403/503 without specific markers
    """
    try:
        text = response.text[:3000]  # Only check first 3 KB
    except Exception:
        text = ""

    if any(m in text for m in CLOUDFLARE_CHALLENGE_MARKERS):
        return "challenge"

    status = getattr(response, "status_code", 0)
    if status == 429 or any(m.lower() in text.lower() for m in RATE_LIMIT_MARKERS):
        return "rate_limit"

    if any(m.lower() in text.lower() for m in GENERIC_WAF_MARKERS):
        return "waf_block"

    if status in (403, 503):
        return "generic_block"

    return "unknown"
