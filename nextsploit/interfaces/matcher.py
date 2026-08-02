"""
nextsploit/interfaces/matcher.py — IMatcherStrategy protocol contract.
"""

from typing import Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    import requests as req_lib
    from nextsploit.interfaces.rule import MatchCondition


class IMatcherStrategy(Protocol):
    """
    Protocol for all condition matchers in the Rule Engine.
    Each matcher is responsible for evaluating a single MatchCondition
    against an HTTP response.
    """

    def match(self, response: "req_lib.Response", condition: "MatchCondition") -> bool:
        """
        Evaluate whether the response satisfies the given condition.

        Args:
            response: The HTTP response from the rule's request.
            condition: The MatchCondition dataclass to evaluate.

        Returns:
            True if the condition is satisfied, False otherwise.
        """
        ...
