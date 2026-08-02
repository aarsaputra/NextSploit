"""
nextsploit/services/policy.py — Policy Engine loader with extends inheritance support.
"""

import os
import json
from typing import Dict, Any, List, Optional
from nextsploit.interfaces.policy import IPolicy


class Policy(IPolicy):
    """
    Concrete implementation of IPolicy that loads profiles and manages policy constraints.
    Supports inheritance via the 'extends' property.
    """

    def __init__(self, name: str, data: Dict[str, Any]):
        self._name = name
        self._data = data

    @property
    def name(self) -> str:
        return self._name

    def is_phase_allowed(self, phase: str) -> bool:
        return phase in self._data.get("allowed_phases", [])

    def get_max_requests(self) -> int:
        return self._data.get("max_requests", 0)

    def get_rate_limit(self) -> int:
        return self._data.get("rate_limit", 0)

    def is_active_testing_allowed(self) -> bool:
        return self._data.get("active_testing", False)

    def get_allowed_severities(self) -> List[str]:
        return self._data.get("allowed_severities", ["low", "medium", "high", "critical"])

    def get_timeout(self) -> int:
        return self._data.get("timeout", 10)

    def get_option(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)


class PolicyEngine:
    """
    Loads, parses, and resolves policies with inheritance.
    """

    def __init__(self, policies_dir: str = "nextsploit/policies"):
        self.policies_dir = policies_dir
        self._loaded_policies: Dict[str, Dict[str, Any]] = {}

    def load_policy(self, policy_name: str) -> Policy:
        """
        Load policy by name. If it extends another policy, load the base first.
        """
        raw_data = self._read_policy_file(policy_name)
        resolved_data = self._resolve_inheritance(raw_data)
        return Policy(policy_name, resolved_data)

    def _read_policy_file(self, name: str) -> Dict[str, Any]:
        filename = f"{name}.json"
        filepath = os.path.join(self.policies_dir, filename)
        
        # Fallback to current directory or system defaults if directory doesn't exist
        if not os.path.exists(filepath):
            # Return a default bare minimum if not found
            return {
                "name": name,
                "active_testing": False,
                "rate_limit": 5,
                "concurrency": 2,
                "timeout": 10,
                "allowed_severities": ["low", "medium", "high", "critical"],
                "allowed_phases": ["Target Validation", "Recon & WAF Detection", "Fingerprinting"]
            }

        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    def _resolve_inheritance(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively resolve the 'extends' property of a policy."""
        parent_name = data.get("extends")
        if not parent_name:
            return data

        # Load parent configuration
        parent_raw = self._read_policy_file(parent_name)
        parent_resolved = self._resolve_inheritance(parent_raw)

        # Merge parent and child. Child overrides parent.
        merged = dict(parent_resolved)
        for k, v in data.items():
            if k == "extends":
                continue
            if isinstance(v, dict) and k in merged and isinstance(merged[k], dict):
                merged[k] = {**merged[k], **v}
            else:
                merged[k] = v
        return merged
