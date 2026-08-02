"""
plugins/sample_modern_plugin/plugin.py — Sample Modern Plugin using the NextSploit v4 SDK.
"""

from nextsploit.interfaces.plugin_context import PluginContext
from nextsploit.services.reporter import Finding


class SampleModernPlugin:
    """
    Sample modern plugin showcasing the v4 7-step lifecycle.
    """

    def __init__(self):
        self.id = "next.sample.modern"
        self.name = "Sample Modern Plugin"
        self.manifest = {}
        self.execution_completed = False

    def initialize(self, context: PluginContext) -> None:
        pass

    def precondition(self, context: PluginContext) -> bool:
        # Check target is Next.js
        return context.profile.framework == "Next.js"

    def execute(self, context: PluginContext) -> None:
        self.execution_completed = True

    def collect(self, context: PluginContext) -> None:
        pass

    def validate(self, context: PluginContext) -> None:
        pass

    def report(self, context: PluginContext) -> None:
        if self.execution_completed:
            f = Finding(
                id=self.id,
                title="Turbopack Signature Verified (Sample Finding)",
                severity="low",
                confidence=1.0,
                evidence={"message": "Target runs Next.js and has Turbopack signature enabled."}
            )
            context.reporter.add_finding(f)

    def cleanup(self, context: PluginContext) -> None:
        pass
