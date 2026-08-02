"""
nextsploit/pipeline/pipeline.py — ScanPipeline coordinator for NextSploit v4.
"""

from typing import List, Set
from nextsploit.core.context import ScanContext
from nextsploit.pipeline.registry import PhaseRegistry
from nextsploit.pipeline.executor import PhaseExecutor
from nextsploit.core.logger import log_info, log_warning


class ScanPipeline:
    """
    Orchestrates the execution of registered phases in sequence.
    """

    def __init__(self):
        self.registry = PhaseRegistry()
        self.executor = PhaseExecutor()
        self.skipped_phases: Set[str] = set()
        self.only_phases: Set[str] = set()

    def run(self, context: ScanContext) -> None:
        """Run the registered phases sequentially against the context."""
        phases = self.registry.get_all()
        
        for phase in phases:
            if context.is_aborted:
                log_warning("Scan aborted. Skipping remaining phases.")
                break

            # Skip phase if configured
            if phase.name in self.skipped_phases:
                log_info(f"Skipping Phase: {phase.name} (configured via skip rule)")
                context.log_audit(f"Phase Skip: {phase.name}", "Skipped by policy or configuration")
                continue

            if self.only_phases and phase.name not in self.only_phases:
                log_info(f"Skipping Phase: {phase.name} (not in only-run set)")
                continue

            self.executor.execute(phase, context)
