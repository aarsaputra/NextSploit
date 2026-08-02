"""
nextsploit/core/kb.py — Knowledge Base (KB) Loader for NextSploit v4.
Loads definitions from fingerprints, vulnerabilities, and heuristics.
"""

import os
import json
from typing import Dict, Any, List, Optional


class KnowledgeBase:
    """
    Manages loading and querying rules, signatures, and vulnerability definitions.
    """

    def __init__(self, root_dir: str = "knowledge"):
        self.root_dir = root_dir
        self.fingerprints: Dict[str, Any] = {}
        self.vulnerabilities: Dict[str, Any] = {}
        self.heuristics: Dict[str, Any] = {}

    def load_all(self) -> None:
        """Scan and load JSON files from knowledge subdirectories."""
        self.fingerprints = self._load_dir("fingerprints")
        self.vulnerabilities = self._load_dir("vulnerabilities")
        self.heuristics = self._load_dir("heuristics")

    def _load_dir(self, subfolder: str) -> Dict[str, Any]:
        """Helper to load all JSON files in a subdirectory."""
        data_map = {}
        target_dir = os.path.join(self.root_dir, subfolder)
        
        # Ensure directory exists
        if not os.path.exists(target_dir):
            os.makedirs(target_dir, exist_ok=True)
            return data_map

        for filename in os.listdir(target_dir):
            if filename.endswith(".json"):
                filepath = os.path.join(target_dir, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        rule_id = data.get("id", filename[:-5])
                        data_map[rule_id] = data
                except Exception:
                    pass
        return data_map

    def get_vulnerability(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific vulnerability definition."""
        return self.vulnerabilities.get(vuln_id)

    def list_vulnerabilities(self) -> List[Dict[str, Any]]:
        """List all loaded vulnerabilities."""
        return list(self.vulnerabilities.values())
