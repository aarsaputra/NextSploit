"""
nextsploit/interfaces/phase.py — Phase Interface Protocol.
"""

from typing import Protocol
from nextsploit.core.context import ScanContext


class IPhase(Protocol):
    """
    Interface contract for execution pipeline phases.
    All phases must implement this protocol.
    """
    name: str

    def run(self, context: ScanContext) -> None:
        """Execute the logic of the phase on the given context."""
        ...
