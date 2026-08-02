"""
nextsploit/services/plugin_loader.py — Manifest validation, module resolver, and plugin discovery.
"""

import os
import json
import sys
import importlib
import importlib.util
from typing import Dict, Any, List, Optional, Tuple

from nextsploit.core.logger import log_info, log_warning, log_debug, log_error
from nextsploit.interfaces.module import IModule
from nextsploit.interfaces.plugin_context import PluginContext


def parse_version_tuple(v_str: str) -> Tuple[int, ...]:
    """Parse a version string (e.g. '15.1.0') into a numeric tuple (15, 1, 0)."""
    parts = []
    for p in v_str.split("."):
        try:
            parts.append(int(p.strip()))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def check_version_constraint(version: str, constraint: str) -> bool:
    """
    Check if a version satisfies a constraint string (e.g., '>=15.0,<16.3' or '>=4.0').
    """
    if not constraint or constraint == "*":
        return True
    
    current_v = parse_version_tuple(version)
    
    # Split by comma for multiple bounds (e.g., '>=15.0,<16.3')
    clauses = constraint.split(",")
    for clause in clauses:
        clause = clause.strip()
        if not clause:
            continue
        
        # Identify operator
        if clause.startswith(">="):
            op, bound_str = ">=", clause[2:]
        elif clause.startswith("<="):
            op, bound_str = "<=", clause[2:]
        elif clause.startswith(">"):
            op, bound_str = ">", clause[1:]
        elif clause.startswith("<"):
            op, bound_str = "<", clause[1:]
        elif clause.startswith("=="):
            op, bound_str = "==", clause[2:]
        else:
            # Assumed as exact version match
            op, bound_str = "==", clause
            
        bound_v = parse_version_tuple(bound_str)
        
        if op == ">=":
            if not (current_v >= bound_v):
                return False
        elif op == "<=":
            if not (current_v <= bound_v):
                return False
        elif op == ">":
            if not (current_v > bound_v):
                return False
        elif op == "<":
            if not (current_v < bound_v):
                return False
        elif op == "==":
            if not (current_v == bound_v):
                return False
                
    return True


class PluginLoader:
    """
    Scans plugins/ folder, validates manifest, resolves dependencies and requirements,
    and returns runnable plugins.
    """

    def __init__(self, plugins_dir: str = "plugins"):
        self.plugins_dir = plugins_dir
        self.loaded_manifests: Dict[str, Dict[str, Any]] = {}
        self.loaded_classes: Dict[str, Any] = {}

    def discover_and_load(self) -> None:
        """Scan plugins directory for manifests and import entry points."""
        if not os.path.exists(self.plugins_dir):
            os.makedirs(self.plugins_dir, exist_ok=True)
            return

        for folder_name in os.listdir(self.plugins_dir):
            folder_path = os.path.join(self.plugins_dir, folder_name)
            if not os.path.isdir(folder_path):
                continue

            manifest_path = os.path.join(folder_path, "manifest.json")
            if not os.path.exists(manifest_path):
                continue

            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    manifest = json.load(f)
                
                # Basic Manifest Validation
                if "id" not in manifest or "entry" not in manifest:
                    log_warning(f"Plugin folder '{folder_name}' has invalid manifest (missing 'id' or 'entry').")
                    continue
                
                plugin_id = manifest["id"]
                
                # Check manifest schema version
                manifest_version = manifest.get("manifest_version", "1.0")
                if manifest_version != "1.0":
                    log_warning(f"Plugin '{plugin_id}' uses unsupported manifest_version '{manifest_version}'.")
                    continue

                # Load module code dynamically
                entry_str = manifest["entry"]
                if ":" not in entry_str:
                    log_warning(f"Plugin '{plugin_id}' entry '{entry_str}' must be in format 'filename.py:ClassName'.")
                    continue

                filename, class_name = entry_str.split(":", 1)
                script_path = os.path.join(folder_path, filename)
                if not os.path.exists(script_path):
                    log_warning(f"Plugin '{plugin_id}' entry script '{script_path}' not found.")
                    continue

                # Dynamic Import using importlib
                spec = importlib.util.spec_from_file_location(f"plugins.{plugin_id}", script_path)
                if spec is None or spec.loader is None:
                    log_warning(f"Could not load spec for plugin '{plugin_id}'.")
                    continue

                mod = importlib.util.module_from_spec(spec)
                # Add directory to sys.path so nested imports inside the plugin work
                sys.path.insert(0, folder_path)
                spec.loader.exec_module(mod)
                sys.path.remove(folder_path)

                cls = getattr(mod, class_name, None)
                if cls is None:
                    log_warning(f"Class '{class_name}' not found in '{script_path}' for plugin '{plugin_id}'.")
                    continue

                # Save metadata
                self.loaded_manifests[plugin_id] = manifest
                self.loaded_classes[plugin_id] = cls
                log_debug(f"Successfully loaded plugin manifest and class for '{plugin_id}'.")

            except Exception as e:
                log_error(f"Failed to load plugin from '{folder_path}': {e}")

    def resolve_plugins(self, context: PluginContext, active_policy_name: str) -> List[Tuple[Dict[str, Any], Any]]:
        """
        Filters and orders loaded plugins based on:
        1. SDK compatibility
        2. Policy checks
        3. Target profile features & version bounds
        4. Dependency graph
        """
        runnable = []
        skipped_ids = set()
        resolved_ids = set()

        # Check active_plugins.json toggles
        toggles = {}
        toggles_path = "nextsploit/policies/active_plugins.json"
        if os.path.exists(toggles_path):
            try:
                with open(toggles_path, "r") as f:
                    toggles = json.load(f)
            except Exception:
                pass

        # Phase 1: Filter individual conditions (SDK, Policy, Profile constraints)
        candidate_ids = list(self.loaded_manifests.keys())
        
        # Sort candidates to handle dependency resolution order (simple topological sort helper)
        # For Sprint 3, we build a simple dependency evaluator
        for pid in candidate_ids:
            # Check toggle status
            if toggles.get(pid) is False:
                log_debug(f"Plugin '{pid}' skipped: Explicitly disabled via plugin configuration.")
                skipped_ids.add(pid)
                continue

            manifest = self.loaded_manifests[pid]
            
            # 1. SDK Version Checks (NextSploit v4 matches >=4.0,<5.0)
            sdk_bound = manifest.get("sdk_version", "4.0")
            if not check_version_constraint("4.0.0", sdk_bound):
                log_warning(f"Plugin '{pid}' skipped: SDK version constraint '{sdk_bound}' not satisfied.")
                skipped_ids.add(pid)
                continue

            # 2. Policy Checks (must be allowed in current active policy)
            allowed_policies = manifest.get("policies", [])
            if allowed_policies and active_policy_name not in allowed_policies:
                log_debug(f"Plugin '{pid}' skipped: Policy '{active_policy_name}' not in allowed list.")
                skipped_ids.add(pid)
                continue

            # 3. Target Profile Capability Requirement Checks
            required_capabilities = manifest.get("requires", [])
            cap_mismatch = False
            for req in required_capabilities:
                # Check boolean status in target profile (e.g. middleware, server_actions)
                if not getattr(context.profile, req, False):
                    log_info(f"Plugin '{pid}' status: [bold yellow]NOT_APPLICABLE[/bold yellow] (missing capability '{req}').")
                    cap_mismatch = True
                    break
            if cap_mismatch:
                skipped_ids.add(pid)
                continue

            # 4. Target Framework Version constraints checking
            fw_constraint = manifest.get("framework")
            if fw_constraint and isinstance(fw_constraint, dict):
                target_version = context.profile.framework_version
                if not target_version:
                    log_info(f"Plugin '{pid}' status: [bold yellow]NOT_APPLICABLE[/bold yellow] (no target framework version detected).")
                    skipped_ids.add(pid)
                    continue
                req_version = fw_constraint.get("version", "*")
                if not check_version_constraint(target_version, req_version):
                    log_info(f"Plugin '{pid}' status: [bold yellow]NOT_APPLICABLE[/bold yellow] (target version '{target_version}' does not match '{req_version}').")
                    skipped_ids.add(pid)
                    continue

            resolved_ids.add(pid)

        # Phase 2: Dependency Graph Resolution
        final_list = []
        for pid in list(resolved_ids):
            manifest = self.loaded_manifests[pid]
            deps = manifest.get("dependencies", [])
            
            # Check if all listed dependencies resolved successfully
            dep_mismatch = False
            for dep in deps:
                if dep not in resolved_ids:
                    log_warning(f"Plugin '{pid}' status: [bold yellow]NOT_APPLICABLE[/bold yellow] (dependency '{dep}' missing or skipped).")
                    dep_mismatch = True
                    break
            if dep_mismatch:
                skipped_ids.add(pid)
                continue
                
            final_list.append((manifest, self.loaded_classes[pid]))
            
        return final_list
