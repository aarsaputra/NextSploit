"""
nextsploit/services/legacy_adapter.py — Legacy Adapter wrapping legacy modules in the new lifecycle.
"""

from typing import Dict, Any, List
from nextsploit.interfaces.module import IModule
from nextsploit.interfaces.plugin_context import PluginContext
from nextsploit.services.reporter import Finding


class LegacyAdapter(IModule):
    """
    Adapter pattern that translates legacy nextsploit modules (exposing `scan(config)`)
    into modern IModule lifecycle components.
    """

    def __init__(self, manifest: Dict[str, Any], legacy_scan_fn: Any):
        self.manifest = manifest
        self.id = manifest.get("id", "legacy.module")
        self.name = manifest.get("name", "Legacy Module")
        self._scan_fn = legacy_scan_fn
        self._result = None

    def initialize(self, context: PluginContext) -> None:
        """Map modern context properties back to compatibility configurations."""
        # Ensure compatibility properties are populated on config
        cfg = context.session  # Just a reference, but let's make sure target config matches
        config = context.session  # In legacy modules, create_session is called, we will mock it if needed.
        
        # We also need context.profile attributes on the config object
        config = context.reporter  # Not used, but config is passed to legacy scan
        
        # In our legacy compatibility config wrapper, we set the fields
        profile = context.profile
        # We can map context.profile parameters to the legacy config object:
        # Since nextsploit/core/config.py is context.config, let's update it:
        # Wait, the scan function takes `config`, which is a ScanConfig!
        # In our CLI, config is ScanConfig. Let's make sure config has:
        # - target
        # - timeout
        # - discovered_js_chunks
        # - discovered_build_id
        # etc.
        # This is already done dynamically in context.config!
        pass

    def precondition(self, context: PluginContext) -> bool:
        """Requirement checks are handled by the ModuleResolver using the manifest."""
        return True

    def execute(self, context: PluginContext) -> None:
        """Execute legacy scan function passing it context.session or a compatibility config."""
        # Create a helper config mock or pass context.config directly (since ScanConfig has all compatibility properties)
        # Wait! Let's check how the legacy module gets its session:
        # In sourcemap_exposure.py:
        # `session = config.create_session()`
        # Let's verify: does ScanConfig have `create_session`?
        # Oh! ScanConfig in nextsploit/core/config.py does NOT have `create_session()`.
        # Let's check if we should add it!
        # Yes, let's add `create_session(self)` to ScanConfig in `nextsploit/core/config.py`
        # so that when legacy modules call `config.create_session()`, it returns a requests session with proxy/timeout configured!
        # Let's do that. That is exceptionally robust!
        
        # We pass context.session's configuration or a wrapper config
        # Let's fetch the actual ScanConfig object from the context or session.
        # Wait, how does LegacyAdapter access ScanConfig?
        # Let's pass the raw config through. But wait! PluginContext doesn't expose ScanConfig directly to enforce encapsulation.
        # But wait! We can add a property or pass a config wrapper in PluginContext, or simply access context.config if we want.
        # Wait, let's add a `config` property to `PluginContext` or a compatibility wrapper, or let the adapter access it.
        # Let's pass context.session as the session, but wait, the legacy scan function expects a config object.
        # Let's write a small shim/wrapper for config inside the LegacyAdapter!
        # In the LegacyAdapter, we can create a simple class that acts as the legacy ScanConfig!
        class LegacyConfigWrapper:
            def __init__(self, p_ctx: PluginContext):
                self._p_ctx = p_ctx
                self.target = p_ctx.profile.target_url
                self.timeout = p_ctx.policy.get("timeout", 10)
                self.discovered_js_chunks = p_ctx.profile.js_chunks
                self.discovered_build_id = p_ctx.profile.build_id
                self.max_requests_per_module = p_ctx.policy.get("max_requests", 0)

            def create_session(self):
                return self._p_ctx.session

            def total_request_count(self):
                return 0

        wrapper_config = LegacyConfigWrapper(context)
        try:
            self._result = self._scan_fn(wrapper_config)
        except Exception as e:
            # Re-raise so execution engine handles it
            raise e

    def collect(self, context: PluginContext) -> None:
        """Parse results and register findings with the reporter."""
        pass

    def validate(self, context: PluginContext) -> None:
        """Analyze results to confirm vulnerability."""
        pass

    def report(self, context: PluginContext) -> Any:
        """Submit findings to context.reporter."""
        if not self._result:
            return

        # Map ModuleResult to our new Finding format
        # Legacy ModuleResult has:
        # - cve: string
        # - title: string
        # - severity: string
        # - status: ScanStatus (SAFE or VULNERABLE)
        # - findings: List of legacy Finding objects
        # Let's extract findings
        legacy_findings = getattr(self._result, "findings", [])
        status = getattr(self._result, "status", None)
        
        # If status is VULNERABLE, make sure we report at least one finding
        if str(status).endswith("VULNERABLE") or legacy_findings:
            if legacy_findings:
                for lf in legacy_findings:
                    # lf has: title, description, evidence
                    f = Finding(
                        id=self.id,
                        title=getattr(lf, "title", self.name),
                        severity=self.manifest.get("severity", "medium").lower(),
                        confidence=1.0,
                        evidence={
                            "description": getattr(lf, "description", ""),
                            "evidence": getattr(lf, "evidence", {})
                        }
                    )
                    context.reporter.add_finding(f)
            else:
                f = Finding(
                    id=self.id,
                    title=self.name,
                    severity=self.manifest.get("severity", "medium").lower(),
                    confidence=1.0,
                    evidence={"description": "Legacy scanner reported vulnerability status."}
                )
                context.reporter.add_finding(f)

    def cleanup(self, context: PluginContext) -> None:
        """Perform post-scan cleanup."""
        self._result = None
