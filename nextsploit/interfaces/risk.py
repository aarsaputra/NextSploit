"""
nextsploit/interfaces/risk.py — Risk Engine Interface.
"""

from typing import Protocol, Any
from nextsploit.interfaces.reporter import IFinding


class IRiskEngine(Protocol):
    """
    Interface contract for calculating severity, confidence, and WAF noise correlation.
    """
    def calculate_cvss(self, finding: IFinding) -> float:
        """Calculate CVSS score for a verified finding."""
        ...

    def evaluate_confidence(self, finding: IFinding, context: Any) -> float:
        """Determine computed confidence score based on evidence validity and CDN/WAF status."""
        ...
