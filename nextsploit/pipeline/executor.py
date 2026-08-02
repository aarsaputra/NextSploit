"""
nextsploit/pipeline/executor.py — Phase Executor for executing individual phases.
"""

import time
from nextsploit.interfaces.phase import IPhase
from nextsploit.core.context import ScanContext
from nextsploit.core.logger import log_info, log_error, log_trace
from nextsploit.core.exceptions import PipelineException


class PhaseExecutor:
    """
    Executes a single phase, measuring its performance and managing errors.
    """

    def execute(self, phase: IPhase, context: ScanContext) -> None:
        """Run the specified phase against the ScanContext."""
        log_info(f"Starting Phase: [bold yellow]{phase.name}[/bold yellow]...")
        start_time = time.monotonic()
        
        try:
            context.current_phase = phase.name
            phase.run(context)
            duration = time.monotonic() - start_time
            log_trace(f"Phase {phase.name} execution completed in {duration:.4f}s.")
            context.log_audit(f"Phase Run: {phase.name}", f"Executed successfully in {duration:.4f}s")
        except Exception as e:
            duration = time.monotonic() - start_time
            log_error(f"Phase {phase.name} failed after {duration:.2f}s: {e}")
            context.log_audit(f"Phase Run: {phase.name}", f"Failed: {e}", status="FAILED")
            raise PipelineException(f"Pipeline failed at phase '{phase.name}': {e}") from e
