"""
nextsploit/interfaces/module.py — Module Lifecycle Interface.
"""

from typing import Protocol, Dict, Any
from nextsploit.interfaces.plugin_context import PluginContext


class IModule(Protocol):
    """
    Interface contract for scanner modules.
    Ensures standard lifecycle steps for vulnerability detection.
    """
    id: str
    name: str
    manifest: Dict[str, Any]

    def initialize(self, context: PluginContext) -> None:
        """Set up initial parameters and scan requirements."""
        ...

    def precondition(self, context: PluginContext) -> bool:
        """Check if target satisfies requirements (e.g. app router, build ID)."""
        ...

    def execute(self, context: PluginContext) -> None:
        """Execute active or passive detection routines."""
        ...

    def collect(self, context: PluginContext) -> None:
        """Collect HTTP requests, responses, and intermediate telemetry."""
        ...

    def validate(self, context: PluginContext) -> None:
        """Analyze gathered evidence to confirm vulnerabilities."""
        ...

    def report(self, context: PluginContext) -> Any:
        """Format and submit findings to the centralized reporter."""
        ...

    def cleanup(self, context: PluginContext) -> None:
        """Flush temporary files, variables, or connections."""
        ...

