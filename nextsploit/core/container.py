"""
nextsploit/core/container.py — Service Container for Dependency Injection in NextSploit.
"""

import threading
from typing import Dict, Any, Type, Callable


class ServiceContainer:
    """
    Thread-safe Dependency Injection Service Container.
    Allows registering and resolving core services by interface or key.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._registry: Dict[Any, Callable[[], Any]] = {}
        self._instances: Dict[Any, Any] = {}

    def register(self, key: Any, factory: Callable[[], Any], singleton: bool = True) -> None:
        """Register a service factory."""
        with self._lock:
            self._registry[key] = factory
            if not singleton and key in self._instances:
                del self._instances[key]

    def register_instance(self, key: Any, instance: Any) -> None:
        """Register an existing service instance directly as a singleton."""
        with self._lock:
            self._instances[key] = instance

    def resolve(self, key: Any) -> Any:
        """Resolve a service by key/interface."""
        with self._lock:
            if key in self._instances:
                return self._instances[key]
            
            if key in self._registry:
                factory = self._registry[key]
                instance = factory()
                self._instances[key] = instance
                return instance

            raise KeyError(f"Service '{key}' is not registered in the container.")

    def reset(self) -> None:
        """Clear all registered services and instances."""
        with self._lock:
            self._registry.clear()
            self._instances.clear()


# Global central container instance
container = ServiceContainer()
