"""
nextsploit/services/metrics.py — Metrics Service tracking request volume, latency, status codes, and plugin timing.
"""

import threading
from typing import Dict, Any, List
from nextsploit.core.constants import Events


class MetricsService:
    """
    Tracks scanning telemetry, HTTP latencies, WAF blocks, and plugin durations.
    Decoupled via subscribing to EventBus events.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.total_requests = 0
        self.responses_received = 0
        self.waf_blocks = 0
        self.failed_requests = 0  # status_code >= 400 or exception/timeout
        self.latencies: List[float] = []
        self.plugin_durations: Dict[str, float] = {}

    def attach_to_event_bus(self, event_bus: Any) -> None:
        """Register metric handlers to the central event bus."""
        event_bus.subscribe(Events.REQUEST_SENT, self._on_request_sent)
        event_bus.subscribe(Events.REQUEST_RECEIVED, self._on_request_received)
        event_bus.subscribe(Events.MODULE_FINISHED, self._on_plugin_finished)

    def _on_request_sent(self, data: Any) -> None:
        with self._lock:
            self.total_requests += 1

    def _on_request_received(self, data: Any) -> None:
        """
        Data expected format:
        {
            "status_code": int,
            "duration": float, # seconds
            "is_waf": bool
        }
        """
        if not isinstance(data, dict):
            return
        
        status_code = data.get("status_code", 200)
        duration = data.get("duration", 0.0)
        is_waf = data.get("is_waf", False)

        with self._lock:
            self.responses_received += 1
            if duration > 0:
                self.latencies.append(duration)
            if is_waf:
                self.waf_blocks += 1
            if status_code >= 400 or status_code == 0:
                self.failed_requests += 1

    def _on_plugin_finished(self, data: Any) -> None:
        """
        Data expected format:
        {
            "plugin_id": str,
            "duration": float
        }
        """
        if not isinstance(data, dict):
            return
        plugin_id = data.get("plugin_id")
        duration = data.get("duration", 0.0)
        if plugin_id:
            with self._lock:
                self.plugin_durations[plugin_id] = duration

    def get_stats(self) -> Dict[str, Any]:
        """Compile and return formatted metrics."""
        with self._lock:
            avg_latency = sum(self.latencies) / len(self.latencies) if self.latencies else 0.0
            success_rate = (
                ((self.responses_received - self.failed_requests) / self.responses_received) * 100
                if self.responses_received else 100.0
            )
            return {
                "total_requests": self.total_requests,
                "responses_received": self.responses_received,
                "failed_requests": self.failed_requests,
                "waf_blocks": self.waf_blocks,
                "average_latency_ms": round(avg_latency * 1000, 2),
                "success_rate_percent": round(success_rate, 2),
                "plugin_durations": dict(self.plugin_durations),
            }
