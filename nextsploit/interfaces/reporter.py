"""
nextsploit/interfaces/reporter.py — Reporter, Formatter, and Exporter Interfaces.
"""

from typing import Protocol, List, Any, Dict


class IFinding(Protocol):
    """Represents a discovered security finding."""
    id: str
    title: str
    severity: str
    confidence: float
    evidence: Dict[str, Any]


class IReporter(Protocol):
    """
    Interface contract for collecting and managing vulnerabilities.
    """
    def add_finding(self, finding: IFinding) -> None:
        """Submit a newly discovered vulnerability finding."""
        ...

    def get_findings(self) -> List[IFinding]:
        """Retrieve all currently logged findings."""
        ...


class IFormatter(Protocol):
    """
    Interface contract for structuring report data into specific outputs.
    """
    def format(self, findings: List[IFinding], metadata: Dict[str, Any]) -> Any:
        """Translate findings list and scan metadata into the target format."""
        ...


class IExporter(Protocol):
    """
    Interface contract for writing structured outputs to files/networks.
    """
    def export(self, formatted_content: Any, destination: str) -> None:
        """Save formatted content to the destination path."""
        ...
