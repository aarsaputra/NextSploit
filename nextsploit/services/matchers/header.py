"""nextsploit/services/matchers/header.py — HTTP response header matcher."""

import requests
from nextsploit.interfaces.rule import MatchCondition


class HeaderMatcher:
    """
    Evaluates response header conditions.
    Supports operators: exists, not_exists, equals, contains.
    The condition value is the header name (for exists/not_exists)
    or a dict {"name": ..., "value": ...} for equals/contains.
    """

    def match(self, response: requests.Response, condition: MatchCondition) -> bool:
        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        if condition.operator == "exists":
            header_name = str(condition.value).lower()
            return header_name in headers_lower

        elif condition.operator == "not_exists":
            header_name = str(condition.value).lower()
            return header_name not in headers_lower

        elif condition.operator == "regex":
            # value is the header name; checks any header value matching the pattern
            # OR value is a dict {"name": ..., "pattern": ...} for specific header
            import re
            if isinstance(condition.value, dict):
                name = str(condition.value.get("name", "")).lower()
                pattern = str(condition.value.get("pattern", ""))
                target_val = headers_lower.get(name, "")
            else:
                # Check all header values against the pattern
                pattern = str(condition.value)
                target_val = " ".join(headers_lower.values())
            try:
                return bool(re.search(pattern, target_val, re.IGNORECASE))
            except re.error:
                return False

        elif condition.operator in ("equals", "contains"):
            # value should be {"name": "header-name", "value": "expected-value"}
            if not isinstance(condition.value, dict):
                return False
            name = str(condition.value.get("name", "")).lower()
            expected = str(condition.value.get("value", ""))
            actual = headers_lower.get(name, "")
            if condition.operator == "equals":
                return actual == expected
            else:  # contains
                return expected.lower() in actual.lower()

        return False
