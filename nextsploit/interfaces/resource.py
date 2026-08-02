"""
nextsploit/interfaces/resource.py — Resource Management Interfaces.
"""

from typing import Protocol, Any


class IResourceManager(Protocol):
    """
    Interface contract for request pooling, timeouts, backoff, and circuit breakers.
    """
    def acquire(self) -> None:
        """Acquire lock block respecting policy rate limits."""
        ...

    def record_response(self, status_code: int) -> None:
        """Feed HTTP status to adaptive rate limiters and circuit breakers."""
        ...

    def is_circuit_broken(self) -> bool:
        """Check if target host is tarpitting or blocking traffic completely."""
        ...
