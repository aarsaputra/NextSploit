"""nextsploit/services/matchers/json_matcher.py — JSONPath-style key/value matcher for JSON responses."""

import requests
from nextsploit.interfaces.rule import MatchCondition


def _get_nested(data: dict, key_path: str):
    """Traverse nested dict using dot-notation key path (e.g. 'error.code')."""
    parts = key_path.split(".")
    current = data
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


class JsonMatcher:
    """
    Evaluates conditions against parsed JSON response bodies.
    Condition value is a dict: {"key": "error.code", "value": 403}
    Operators: equals, contains, exists, not_exists.
    """

    def match(self, response: requests.Response, condition: MatchCondition) -> bool:
        try:
            data = response.json()
        except Exception:
            return False

        if not isinstance(condition.value, dict):
            return False

        key_path = str(condition.value.get("key", ""))
        expected = condition.value.get("value")
        actual = _get_nested(data, key_path)

        if condition.operator == "exists":
            return actual is not None
        elif condition.operator == "not_exists":
            return actual is None
        elif condition.operator == "equals":
            return actual == expected
        elif condition.operator == "contains":
            if isinstance(actual, str) and isinstance(expected, str):
                return expected.lower() in actual.lower()
            return False

        return False
