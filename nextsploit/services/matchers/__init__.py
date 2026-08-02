"""
nextsploit/services/matchers/__init__.py — MatcherRegistry: maps condition type strings to strategy instances.
"""

from typing import Dict
from nextsploit.interfaces.matcher import IMatcherStrategy
from nextsploit.services.matchers.status import StatusMatcher
from nextsploit.services.matchers.header import HeaderMatcher
from nextsploit.services.matchers.regex import RegexMatcher
from nextsploit.services.matchers.json_matcher import JsonMatcher
from nextsploit.services.matchers.timing import TimingMatcher


class MatcherRegistry:
    """Central registry mapping condition type strings to IMatcherStrategy instances."""

    def __init__(self) -> None:
        self._registry: Dict[str, IMatcherStrategy] = {
            "status": StatusMatcher(),
            "header": HeaderMatcher(),
            "regex": RegexMatcher(),
            "json": JsonMatcher(),
            "timing": TimingMatcher(),
        }

    def get(self, condition_type: str) -> IMatcherStrategy:
        matcher = self._registry.get(condition_type)
        if matcher is None:
            raise ValueError(f"No matcher registered for condition type '{condition_type}'.")
        return matcher

    def register(self, condition_type: str, matcher: IMatcherStrategy) -> None:
        """Allows external registration of custom matchers."""
        self._registry[condition_type] = matcher


# Module-level singleton registry
default_registry = MatcherRegistry()
