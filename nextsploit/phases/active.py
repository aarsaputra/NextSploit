"""
nextsploit/phases/active.py — Phase 3: Active Testing & Plugin Execution Phase.
Discovers, resolves, and executes registered plugins with strict isolation and error handling.
"""

import time
import concurrent.futures
from typing import Dict, Any, List

from nextsploit.core.context import ScanContext
from nextsploit.core.logger import log_info, log_success, log_warning, log_error, log_debug
from nextsploit.interfaces.plugin_context import PluginContext
from nextsploit.services.plugin_loader import PluginLoader
from nextsploit.services.policy import PolicyEngine


class PluginExecutionPhase:
    """
    Phase 3: Active Testing.
    Loads plugins, filters candidates via Policy & Module Resolver, and executes
    resolved plugin lifecycles under strict isolation.
    """
    name = "Active Testing"

    def run(self, context: ScanContext) -> None:
        log_info("Starting Plugin Execution Phase...")

        # 1. Initialize PluginLoader and discover plugins
        loader = PluginLoader()
        loader.discover_and_load()

        if not loader.loaded_manifests:
            log_info("No plugins discovered in plugins/ directory.")
            return

        log_info(f"Discovered {len(loader.loaded_manifests)} plugin(s). Resolving eligibility...")

        # 2. Get active policy name and load its constraints
        policy_name = context.config.policy_name
        policy_engine = PolicyEngine()
        policy = policy_engine.load_policy(policy_name)
        
        # Verify if Active Testing is allowed under current policy
        if not policy.is_active_testing_allowed():
            log_info(f"Active testing plugins are disabled under the current policy profile: [bold cyan]{policy_name}[/bold cyan]")
            # We will only run passive plugins if policy says active_testing is False
            # Wait, let's load all candidate plugins and filter
            pass

        # Retrieve central services
        from nextsploit.core.container import container
        reporter = container.resolve("reporter")
        from nextsploit.core.kb import KnowledgeBase
        kb = KnowledgeBase()
        kb.load_all()

        # Build policy options dictionary for PluginContext
        policy_dict = {
            "name": policy.name,
            "active_testing": policy.is_active_testing_allowed(),
            "timeout": policy.get_timeout(),
            "rate_limit": policy.get_rate_limit(),
            "allowed_severities": policy.get_allowed_severities(),
        }

        # 3. Create PluginContext
        p_ctx = PluginContext(
            profile=context.profile,
            reporter=reporter,
            session=context.session,
            kb=kb,
            policy=policy_dict
        )

        # 4. Filter and resolve runnable plugins
        runnable = loader.resolve_plugins(p_ctx, policy_name)
        if not runnable:
            log_info("No plugins resolved for execution against the target profile.")
            return

        log_info(f"Resolved [bold green]{len(runnable)}[/bold green] eligible plugin(s) for execution.")

        # 5. Execute each plugin with isolation and timeouts
        for manifest, plugin_class in runnable:
            plugin_id = manifest["id"]
            plugin_name = manifest.get("name", plugin_id)
            
            # Check if plugin is active but policy forbids active testing
            is_plugin_active = manifest.get("phase", "active") == "active"
            if is_plugin_active and not policy.is_active_testing_allowed():
                log_debug(f"Skipping active plugin '{plugin_id}' because active testing is disabled in policy.")
                continue

            log_info(f"Running plugin: [bold cyan]{plugin_name}[/bold cyan] ({plugin_id})...")
            
            # Initialize module instance
            try:
                # Handle legacy adapter instantiation vs modern class
                # If it's a legacy entry, the plugin_class is the scan function itself,
                # so we instantiate LegacyAdapter
                if not hasattr(plugin_class, "initialize") and callable(plugin_class):
                    from nextsploit.services.legacy_adapter import LegacyAdapter
                    plugin_instance = LegacyAdapter(manifest, plugin_class)
                else:
                    plugin_instance = plugin_class()
                    # Assign standard attributes
                    plugin_instance.id = plugin_id
                    plugin_instance.name = plugin_name
                    plugin_instance.manifest = manifest

            except Exception as e:
                log_error(f"Failed to instantiate plugin '{plugin_id}': {e}")
                continue

            # Run full 7-step isolated lifecycle
            timeout = policy.get_timeout()
            self._run_isolated_lifecycle(plugin_instance, p_ctx, plugin_id, timeout)

        log_success("Plugin Execution Phase completed.")

    def _run_isolated_lifecycle(self, plugin: Any, p_ctx: PluginContext, plugin_id: str, timeout: int) -> None:
        """Run lifecycle phases with execution bounds and isolation."""
        lifecycle = ["initialize", "precondition", "execute", "collect", "validate", "report", "cleanup"]
        
        start_time = time.monotonic()
        try:
            # We run steps with executor to capture timeouts on execution
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                for step in lifecycle:
                    fn = getattr(plugin, step, None)
                    if not fn:
                        continue
                    
                    log_debug(f"Plugin '{plugin_id}' -> executing step '{step}'")
                    
                    if step == "precondition":
                        future = executor.submit(fn, p_ctx)
                        res = future.result(timeout=timeout)
                        if not res:
                            log_info(f"Plugin '{plugin_id}' preconditions failed. Skipping remaining steps.")
                            break
                    else:
                        future = executor.submit(fn, p_ctx)
                        future.result(timeout=timeout)

            duration = time.monotonic() - start_time
            log_debug(f"Plugin '{plugin_id}' finished successfully in {duration:.3f}s.")
            
            # Publish plugin finished metrics
            from nextsploit.core.constants import Events
            from nextsploit.core.container import container
            try:
                eb = container.resolve("event_bus")
                eb.publish(Events.MODULE_FINISHED, {"plugin_id": plugin_id, "duration": duration})
            except KeyError:
                pass

        except concurrent.futures.TimeoutError:
            log_error(f"Plugin '{plugin_id}' timed out after {timeout} seconds during execution.")
            # Always call cleanup on failure/timeout to flush state
            try:
                plugin.cleanup(p_ctx)
            except Exception:
                pass
        except Exception as e:
            log_error(f"Plugin '{plugin_id}' crashed: {e}")
            # Ensure cleanup is run
            try:
                plugin.cleanup(p_ctx)
            except Exception:
                pass
