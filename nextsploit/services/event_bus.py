"""
nextsploit/services/event_bus.py — Central Event Bus implementation.
"""

import threading
from typing import Dict, List, Callable, Any
from nextsploit.interfaces.event import IEventBus


class EventBus(IEventBus):
    """
    Thread-safe publish-subscribe Event Bus for decoupling framework services.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._subscribers: Dict[str, List[Callable[[Any], None]]] = {}

    def subscribe(self, event_name: str, handler: Callable[[Any], None]) -> None:
        """Register a callback handler for a specific event."""
        with self._lock:
            if event_name not in self._subscribers:
                self._subscribers[event_name] = []
            self._subscribers[event_name].append(handler)

    def publish(self, event_name: str, data: Any) -> None:
        """Publish data to all registered event handlers."""
        # Retrieve handlers under lock to prevent mutation during iteration
        handlers = []
        with self._lock:
            if event_name in self._subscribers:
                handlers = list(self._subscribers[event_name])

        for handler in handlers:
            try:
                handler(data)
            except Exception as e:
                # Log or swallow listener exceptions to keep the publisher isolated
                # We can write a simple debug print or ignore
                pass
