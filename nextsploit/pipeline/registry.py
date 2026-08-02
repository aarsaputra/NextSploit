"""
nextsploit/pipeline/registry.py — Phase Registry for NextSploit v4.
"""

from typing import List, Dict, Optional
from nextsploit.interfaces.phase import IPhase


class PhaseRegistry:
    """
    Manages and registers the pipeline phases sequentially.
    """

    def __init__(self):
        self._phases: List[IPhase] = []
        self._phase_map: Dict[str, IPhase] = {}

    def register(self, phase: IPhase) -> None:
        """Register a phase in the sequence."""
        if phase.name in self._phase_map:
            # Overwrite or ignore duplicates
            return
        self._phases.append(phase)
        self._phase_map[phase.name] = phase

    def get_all(self) -> List[IPhase]:
        """Return all registered phases in order."""
        return self._phases

    def get(self, name: str) -> Optional[IPhase]:
        """Retrieve a specific phase by name."""
        return self._phase_map.get(name)

    def clear(self) -> None:
        """Clear all registered phases."""
        self._phases.clear()
        self._phase_map.clear()
