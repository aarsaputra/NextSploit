"""
nextsploit/interfaces/policy.py — Policy Engine Interface.
"""

from typing import Protocol, Dict, Any, Optional


class IPolicy(Protocol):
    """
    Interface contract representing a security scan policy profile.
    """
    name: str
    parent_policy: Optional[str]

    def is_phase_allowed(self, phase_name: str) -> bool:
        """Check if the given phase is allowed under this policy."""
        ...

    def is_active_validation_allowed(self, severity_level: str) -> bool:
        """Check if active tests of specified severity levels are allowed."""
        ...

    def get_rate_limit(self) -> int:
        """Retrieve the configured maximum requests per second constraint."""
        ...

    def get_raw_config(self) -> Dict[str, Any]:
        """Get the raw key-value mapping of policy settings."""
        ...
