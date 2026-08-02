"""nextsploit/services/matchers/timing.py — Response timing matcher for timing-based detection."""

import requests
from nextsploit.interfaces.rule import MatchCondition


class TimingMatcher:
    """
    Evaluates response elapsed time conditions.
    Useful for detecting time-based SQL injection, sleep-based SSRF, etc.
    Operators: gt (elapsed > value), lt (elapsed < value).
    Value is seconds as a float.
    """

    def match(self, response: requests.Response, condition: MatchCondition) -> bool:
        try:
            elapsed = response.elapsed.total_seconds()
            threshold = float(condition.value)
        except (AttributeError, TypeError, ValueError):
            return False

        if condition.operator == "gt":
            return elapsed > threshold
        elif condition.operator == "lt":
            return elapsed < threshold

        return False
