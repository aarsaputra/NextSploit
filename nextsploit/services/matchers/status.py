"""nextsploit/services/matchers/status.py — HTTP status code matcher."""

import requests
from nextsploit.interfaces.rule import MatchCondition


class StatusMatcher:
    """
    Evaluates HTTP status code conditions.
    Supports operators: equals, lt (less than), gt (greater than).
    """

    def match(self, response: requests.Response, condition: MatchCondition) -> bool:
        actual = response.status_code
        expected = int(condition.value)

        if condition.operator == "equals":
            return actual == expected
        elif condition.operator == "lt":
            return actual < expected
        elif condition.operator == "gt":
            return actual > expected
        return False
