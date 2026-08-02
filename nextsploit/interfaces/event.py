"""
nextsploit/interfaces/event.py — Event Bus Interfaces.
"""

from typing import Protocol, Any, Callable


class IEventHandler(Protocol):
    """
    Interface contract representing an event listener callback.
    """
    def handle(self, event_name: str, data: Any) -> None:
        """Handle incoming published event notifications."""
        ...


class IEventBus(Protocol):
    """
    Interface contract for publish-subscribe event routing.
    """
    def publish(self, event_name: str, data: Any) -> None:
        """Publish an event with metadata to all registered subscribers."""
        ...

    def subscribe(self, event_name: str, handler: Callable[[Any], None]) -> None:
        """Subscribe to notifications for a specific event name."""
        ...
