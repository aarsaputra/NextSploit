#!/usr/bin/env python3
"""
NextSploit — False Positive Reduction Engine v2
Adapted from ppmap for NextSploit

v2 changes:
  - Added is_waf_block() — global WAF/CDN block signature registry
  - Configurable noise_ratio threshold (default 0.8, overridable via ScanConfig)
  - WAF block detection integrated into confidence scoring
"""

import re
import json
from typing import Dict, Any, Tuple


# ─── WAF / CDN Block Signatures ──────────────────────────────────────────────

# HTTP status codes typically emitted by WAF/CDN blocks (not by the app itself)
WAF_BLOCK_STATUS_CODES = {
    432,   # Whaleguard custom block
    444,   # Nginx silent drop
    499,   # Client closed request (Nginx)
    520,   # Cloudflare unknown error
    521,   # Cloudflare web server is down
    522,   # Cloudflare connection timed out
    523,   # Cloudflare origin is unreachable
    524,   # Cloudflare a timeout occurred
    525,   # Cloudflare SSL handshake failed
    526,   # Cloudflare invalid SSL certificate
    530,   # Cloudflare error (1xxx errors)
}

# Body patterns indicating WAF/CDN interference (case-insensitive match)
WAF_BLOCK_BODY_PATTERNS = [
    "whaleguard block",
    "access denied",
    "request blocked",
    "you have been blocked",
    "blocked by",
    "security check",
    "bot protection",
    "ddos protection",
    "error 1020",          # Cloudflare Access Denied
    "error 1010",          # Cloudflare JS challenge
    "__cf_chl",            # Cloudflare challenge JS
    "cloudflare ray id",   # Cloudflare error page
    "cf-browser-verification",
    "akamai reference",    # Akamai block page
    "imperva",
    "incapsula",
    "sucuri website firewall",
    "this website is protected",
    "attention required",  # Cloudflare "Attention Required" page
]

# If body is shorter than this AND status is anomalous, likely a WAF block
WAF_SHORT_BODY_THRESHOLD = 1000  # bytes


def is_waf_block(response) -> bool:
    """
    Returns True if the HTTP response appears to be a WAF/CDN block,
    NOT a legitimate application response.

    Use this before creating any Finding to filter false positives.

    Args:
        response: requests.Response object

    Returns:
        bool: True if this looks like a WAF block
    """
    if response is None:
        return False

    status = getattr(response, "status_code", 0)

    # Check explicit WAF status codes
    if status in WAF_BLOCK_STATUS_CODES:
        return True

    # Check body patterns (case-insensitive)
    try:
        body = response.text[:5000].lower()  # Only scan first 5KB
    except Exception:
        body = ""

    for pattern in WAF_BLOCK_BODY_PATTERNS:
        if pattern.lower() in body:
            return True

    # Short body + non-standard status = likely WAF block
    try:
        body_len = len(response.content)
    except Exception:
        body_len = len(body)

    if body_len < WAF_SHORT_BODY_THRESHOLD and status not in (200, 201, 204, 301, 302, 304, 404):
        # Short body with a redirect or unusual error — likely a WAF challenge page
        if status in (400, 403, 407, 429, 503):
            return True

    return False


def get_waf_block_reason(response) -> str:
    """
    Returns a human-readable reason why this response was identified as a WAF block.
    """
    if response is None:
        return "null response"

    status = getattr(response, "status_code", 0)

    if status in WAF_BLOCK_STATUS_CODES:
        return f"WAF status code {status}"

    try:
        body = response.text[:1000].lower()
    except Exception:
        body = ""

    for pattern in WAF_BLOCK_BODY_PATTERNS:
        if pattern.lower() in body:
            return f"WAF body pattern: '{pattern}'"

    return f"Short body ({len(getattr(response, 'content', b''))} bytes) with status {status}"


# ─── Noise Threshold ─────────────────────────────────────────────────────────

DEFAULT_NOISE_THRESHOLD = 0.8  # 80% noise → INCONCLUSIVE


def exceeds_noise_threshold(noise_ratio: float, threshold: float = DEFAULT_NOISE_THRESHOLD) -> bool:
    """
    Returns True if the noise ratio exceeds the configured threshold,
    meaning results from this module should be downgraded to INCONCLUSIVE.
    """
    return noise_ratio >= threshold


# ─── FP Engine (Prototype Pollution & Differential Analysis) ─────────────────

class FalsePositiveEngine:
    """
    Engine to reduce false positives by validating prototype pollution
    and calculating confidence scores based on response characteristics.
    """

    REFLECTION_PATTERNS = [
        r'"{value}"',
        r"'{value}'",
        r'\"{value}\"',
    ]

    POLLUTION_INDICATORS = [
        r"Object\.prototype\.",
        r"__proto__",
        r"constructor\.prototype",
    ]

    def is_reflected(self, response_text: str, payload: str) -> bool:
        """
        Check if the payload is simply reflected in the response (e.g., in an error message)
        without causing structural changes.
        """
        if not response_text or not payload:
            return False

        try:
            payload_dict = json.loads(payload)
            values_to_check = []

            def extract_values(d):
                if isinstance(d, dict):
                    for v in d.values():
                        extract_values(v)
                elif isinstance(d, list):
                    for v in d:
                        extract_values(v)
                else:
                    values_to_check.append(str(d))

            extract_values(payload_dict)

            for val in values_to_check:
                if val in ["true", "false", "null", "__proto__", "constructor"]:
                    continue
                val_count = response_text.count(val)
                if val_count > 0:
                    return True
        except ValueError:
            if payload in response_text:
                return True

        return False

    def calculate_confidence(self, size_diff: int, is_reflected: bool, response_text: str) -> float:
        """
        Calculate overall confidence score (0.0 to 1.0)
        """
        score = 0.5  # Base score

        if size_diff > 500:
            score += 0.3
        elif size_diff > 200:
            score += 0.1

        if is_reflected:
            score -= 0.4

        if (
            "Application error: a client-side exception has occurred" in response_text
            or "Internal Server Error" in response_text
        ):
            if size_diff < 1000:
                score -= 0.2

        return max(0.0, min(1.0, score))

    def validate_prototype_pollution(
        self,
        baseline_size: int,
        response_size: int,
        baseline_hash: str,
        response_hash: str,
        response_text: str,
        payload: str,
        response=None,
    ) -> Tuple[bool, float, str]:
        """
        Validates prototype pollution and returns (is_valid, confidence, reason).

        Now also checks WAF block signatures before flagging.
        """
        # First: WAF block check — never flag a WAF block as a finding
        if response is not None and is_waf_block(response):
            reason = get_waf_block_reason(response)
            return False, 0.0, f"WAF block — {reason}"

        if response_hash == baseline_hash:
            return False, 0.0, "Response hash matches baseline"

        size_diff = abs(response_size - baseline_size)

        if size_diff < 100:
            return False, 0.1, f"Size difference too small ({size_diff} bytes)"

        is_reflected = self.is_reflected(response_text, payload)
        confidence = self.calculate_confidence(size_diff, is_reflected, response_text)

        if confidence >= 0.5:
            reason = f"Response differs significantly ({size_diff} bytes) with confidence {confidence:.2f}"
            return True, confidence, reason
        else:
            reason = f"Filtered by FP Engine (Reflected: {is_reflected}, Confidence: {confidence:.2f})"
            return False, confidence, reason


_engine = FalsePositiveEngine()


def validate_prototype_pollution(
    baseline_size: int,
    response_size: int,
    baseline_hash: str,
    response_hash: str,
    response_text: str,
    payload: str,
    response=None,
) -> Tuple[bool, float, str]:
    return _engine.validate_prototype_pollution(
        baseline_size, response_size, baseline_hash,
        response_hash, response_text, payload, response,
    )
