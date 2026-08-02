"""nextsploit/services/matchers/regex.py — Regex pattern matcher against response body or headers."""

import re
import requests
from nextsploit.interfaces.rule import MatchCondition


class RegexMatcher:
    """
    Evaluates regex pattern conditions against the response body or a specific header.
    Operators: regex (match), not_exists (no match).
    Location: "body" | "header:<name>"
    """

    def match(self, response: requests.Response, condition: MatchCondition) -> bool:
        pattern = str(condition.value)
        location = condition.location.lower()

        if location == "body":
            target = response.text or ""
        elif location.startswith("header:"):
            header_name = location.split(":", 1)[1].strip()
            target = response.headers.get(header_name, "")
        else:
            target = response.text or ""

        try:
            found = bool(re.search(pattern, target, re.IGNORECASE | re.DOTALL))
        except re.error:
            return False

        if condition.operator == "regex":
            return found
        elif condition.operator == "not_exists":
            return not found
        return False
