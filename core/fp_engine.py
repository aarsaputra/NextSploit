#!/usr/bin/env python3
"""
False Positive Reduction Engine
Adapted from ppmap for NextSploit
"""

import re
import json
from typing import Dict, Any, Tuple

class FalsePositiveEngine:
    """
    Engine to reduce false positives by validating prototype pollution
    and calculating confidence scores based on response characteristics.
    """

    REFLECTION_PATTERNS = [
        r'"{value}"',
        r"'{value}'",
        r'\\"{value}\\"',
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

        # If payload is JSON, extract keys and values to check for reflection
        try:
            payload_dict = json.loads(payload)
            # Flatten to check values
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
            
            # For each value, if it's heavily reflected, it might just be echoing
            for val in values_to_check:
                if val in ["true", "false", "null", "__proto__", "constructor"]:
                    continue # too common
                val_count = response_text.count(val)
                if val_count > 0:
                    return True
        except ValueError:
            # Not JSON, check exact match
            if payload in response_text:
                return True

        return False

    def calculate_confidence(self, size_diff: int, is_reflected: bool, response_text: str) -> float:
        """
        Calculate overall confidence score (0.0 to 1.0)
        """
        score = 0.5  # Base score

        # Boost for significant size difference (likely structural change)
        if size_diff > 500:
            score += 0.3
        elif size_diff > 200:
            score += 0.1

        # Penalty if it's just reflected
        if is_reflected:
            score -= 0.4

        # Penalty for generic Next.js error pages if size diff is minimal
        if "Application error: a client-side exception has occurred" in response_text or "Internal Server Error" in response_text:
            if size_diff < 1000:
                score -= 0.2

        # Clamp
        return max(0.0, min(1.0, score))

    def validate_prototype_pollution(
        self, baseline_size: int, response_size: int, 
        baseline_hash: str, response_hash: str, 
        response_text: str, payload: str
    ) -> Tuple[bool, float, str]:
        """
        Validates prototype pollution and returns (is_valid, confidence, reason).
        """
        if response_hash == baseline_hash:
            return False, 0.0, "Response hash matches baseline"

        size_diff = abs(response_size - baseline_size)
        
        # If difference is too small, it's likely noise (e.g., CSRF token change, timestamp)
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

def validate_prototype_pollution(baseline_size: int, response_size: int, baseline_hash: str, response_hash: str, response_text: str, payload: str) -> Tuple[bool, float, str]:
    return _engine.validate_prototype_pollution(baseline_size, response_size, baseline_hash, response_hash, response_text, payload)
