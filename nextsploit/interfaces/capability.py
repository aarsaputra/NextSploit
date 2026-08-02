"""
nextsploit/interfaces/capability.py — Capability Interfaces.
"""

from typing import Protocol, Any, Dict


class ICapability(Protocol):
    """
    Interface contract representing a target feature capability object.
    """
    name: str
    detected: bool
    confidence: float
    source: str
    evidence: Dict[str, Any]


class ICapabilityRegistry(Protocol):
    """
    Interface contract for capability registration and dependency matching.
    """
    def register(self, capability: ICapability) -> None:
        """Register a discovered target capability."""
        ...

    def get(self, name: str) -> ICapability:
        """Retrieve capability properties by name."""
        ...

    def has(self, name: str) -> bool:
        """Check if target capability exists and is verified."""
        ...
