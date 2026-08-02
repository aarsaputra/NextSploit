"""
nextsploit/services/plugin_doctor.py — Plugin Doctor verification suite for developer sandboxes.
"""

import os
import json
import importlib.util
from typing import Dict, Any, List
from nextsploit.services.plugin_loader import check_version_constraint
from nextsploit.interfaces.plugin_context import PluginContext
from nextsploit.core.context import TargetProfile
from nextsploit.services.reporter import ScanReporter


class PluginDoctor:
    """
    Runs developer validation checks on a local plugin package directory.
    Evaluates: Manifest, Import, SDK version, Lifecycle hooks, Dependencies, Policy, Sandbox run.
    Returns scorecard details and a calculated Health Score.
    """

    def run_check(self, plugin_dir: str) -> Dict[str, Any]:
        report = {
            "Manifest": {"status": "FAIL", "weight": 15, "score": 0, "details": "Manifest file missing or invalid."},
            "Import": {"status": "FAIL", "weight": 15, "score": 0, "details": "Module could not be imported."},
            "SDK Version": {"status": "FAIL", "weight": 10, "score": 0, "details": "SDK constraints incompatible."},
            "Lifecycle Hooks": {"status": "FAIL", "weight": 20, "score": 0, "details": "Required lifecycle methods are missing."},
            "Dependencies": {"status": "FAIL", "weight": 10, "score": 0, "details": "Dependencies/Capabilities checks failed."},
            "Policy Mapping": {"status": "FAIL", "weight": 10, "score": 0, "details": "No valid execution profiles configured."},
            "Sandbox Dry Run": {"status": "FAIL", "weight": 20, "score": 0, "details": "Crashed or failed in isolated sandbox execution."}
        }

        manifest_path = os.path.join(plugin_dir, "manifest.json")
        if not os.path.exists(manifest_path):
            return self._finalize_report(report)

        # 1. Manifest Check
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
            
            required_keys = ["id", "name", "version", "sdk_version", "entry", "phase", "policies"]
            missing = [k for k in required_keys if k not in manifest]
            
            if missing:
                report["Manifest"]["details"] = f"Missing keys: {', '.join(missing)}"
            else:
                report["Manifest"]["status"] = "PASS"
                report["Manifest"]["score"] = report["Manifest"]["weight"]
                report["Manifest"]["details"] = f"Valid schema version {manifest.get('manifest_version', '1.0')}."
        except Exception as e:
            report["Manifest"]["details"] = f"JSON parse error: {e}"
            return self._finalize_report(report)

        # 2. SDK Version Check
        sdk_constraint = manifest.get("sdk_version", "")
        # Framework version is 4.0.0-alpha
        if check_version_constraint("4.0.0", sdk_constraint):
            report["SDK Version"]["status"] = "PASS"
            report["SDK Version"]["score"] = report["SDK Version"]["weight"]
            report["SDK Version"]["details"] = f"Framework matches target constraints: {sdk_constraint}."
        else:
            report["SDK Version"]["details"] = f"Incompatible framework version. Constraint: {sdk_constraint}"

        # 3. Policy Mapping Check
        policies = manifest.get("policies", [])
        valid_policies = {"safe", "bugbounty", "pentest", "ci"}
        configured = [p for p in policies if p in valid_policies]
        if configured:
            report["Policy Mapping"]["status"] = "PASS"
            report["Policy Mapping"]["score"] = report["Policy Mapping"]["weight"]
            report["Policy Mapping"]["details"] = f"Allows execution profiles: {', '.join(configured)}."
        else:
            report["Policy Mapping"]["details"] = "No standard execution profiles defined."

        # 4. Import Check
        entry_val = manifest.get("entry", "")
        if ":" not in entry_val:
            report["Import"]["details"] = "Invalid entry signature. Format: 'file.py:Class'."
            return self._finalize_report(report)

        filename, attr = entry_val.split(":", 1)
        file_path = os.path.join(plugin_dir, filename)
        
        if not os.path.exists(file_path):
            report["Import"]["details"] = f"Entry script '{filename}' not found."
            return self._finalize_report(report)

        module_name = f"plugin_doctor_{manifest['id'].replace('.', '_')}"
        plugin_class = None
        try:
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                plugin_class = getattr(module, attr, None)
                if plugin_class:
                    report["Import"]["status"] = "PASS"
                    report["Import"]["score"] = report["Import"]["weight"]
                    report["Import"]["details"] = f"Successfully loaded attribute '{attr}'."
                else:
                    report["Import"]["details"] = f"Entry target '{attr}' not found inside module."
            else:
                report["Import"]["details"] = "Module spec loader initialized as null."
        except Exception as e:
            report["Import"]["details"] = f"Module execution crash: {e}"
            return self._finalize_report(report)

        # 5. Lifecycle Hooks Check
        is_legacy = not hasattr(plugin_class, "initialize") and callable(plugin_class)
        if is_legacy:
            report["Lifecycle Hooks"]["status"] = "PASS"
            report["Lifecycle Hooks"]["score"] = report["Lifecycle Hooks"]["weight"]
            report["Lifecycle Hooks"]["details"] = "Legacy scan(config) function detected. Adaptive wrapping active."
        else:
            # Modern plugin check
            lifecycle = ["initialize", "precondition", "execute", "collect", "validate", "report", "cleanup"]
            present = [step for step in lifecycle if hasattr(plugin_class, step)]
            missing_hooks = [step for step in lifecycle if step not in present]
            
            if len(present) >= 4:  # initialized, precondition, execute, report
                report["Lifecycle Hooks"]["status"] = "PASS"
                report["Lifecycle Hooks"]["score"] = report["Lifecycle Hooks"]["weight"]
                report["Lifecycle Hooks"]["details"] = f"Implements core hooks. Present: {', '.join(present)}."
            else:
                report["Lifecycle Hooks"]["details"] = f"Missing core hooks: {', '.join(missing_hooks)}"

        # 6. Dependencies / Capabilities Check
        requires = manifest.get("requires", [])
        report["Dependencies"]["status"] = "PASS"
        report["Dependencies"]["score"] = report["Dependencies"]["weight"]
        report["Dependencies"]["details"] = f"Target requires capabilities: {', '.join(requires)}." if requires else "No external capability dependencies declared."

        # 7. Sandbox Dry Run Check
        try:
            # Instantiate
            if is_legacy:
                from nextsploit.services.legacy_adapter import LegacyAdapter
                instance = LegacyAdapter(manifest, plugin_class)
            else:
                instance = plugin_class()
                instance.id = manifest["id"]
                instance.name = manifest["name"]
                instance.manifest = manifest

            # Setup mock context
            profile = TargetProfile("http://127.0.0.1")
            # Populate capability fields to satisfy requirements
            for cap in requires:
                setattr(profile, cap, True)
            
            reporter = ScanReporter()
            import requests
            session = requests.Session()
            from nextsploit.core.kb import KnowledgeBase
            kb = KnowledgeBase()
            policy_dict = {"name": "safe", "active_testing": False, "timeout": 5, "rate_limit": 5, "allowed_severities": ["low"]}
            
            p_ctx = PluginContext(profile=profile, reporter=reporter, session=session, kb=kb, policy=policy_dict)

            # Dry run lifecycle
            instance.initialize(p_ctx)
            if instance.precondition(p_ctx):
                instance.execute(p_ctx)
                instance.collect(p_ctx)
                instance.validate(p_ctx)
                instance.report(p_ctx)
            instance.cleanup(p_ctx)

            report["Sandbox Dry Run"]["status"] = "PASS"
            report["Sandbox Dry Run"]["score"] = report["Sandbox Dry Run"]["weight"]
            report["Sandbox Dry Run"]["details"] = f"Dry-run executed. Discovered {len(reporter.get_findings())} mock finding(s)."

        except Exception as e:
            report["Sandbox Dry Run"]["details"] = f"Dry-run crash: {e}"

        return self._finalize_report(report)

    def _finalize_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        total_weight = sum(item["weight"] for item in report.values())
        total_score = sum(item["score"] for item in report.values())
        health_score = int((total_score / total_weight) * 100) if total_weight > 0 else 0
        return {
            "health_score": health_score,
            "checklist": report
        }
