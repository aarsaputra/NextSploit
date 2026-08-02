"""
nextsploit/phases/rule_execution.py — Pipeline Phase 5: YAML Rule Engine execution.

Intentionally separate from PluginExecutionPhase to:
  - Keep lifecycle, timeouts, and metrics independent.
  - Enable separate enable/disable control.
  - Produce clean telemetry: rule_findings vs plugin_findings.
"""

import time
from nextsploit.interfaces.phase import IPhase
from nextsploit.core.context import ScanContext
from nextsploit.core.logger import log_info, log_warning
from nextsploit.services.rule_engine import RuleLoader, RuleFilter, RuleRunner

RULES_DIR = "knowledge/rules/core"


class RuleExecutionPhase(IPhase):
    """
    Pipeline phase 5 — loads, filters, and executes YAML detection rules.
    Emits RULE_MATCHED events for each confirmed finding.
    """

    @property
    def name(self) -> str:
        return "Rule-Based Detection"

    def run(self, context: ScanContext) -> None:
        log_info("[*] Starting Phase: Rule-Based Detection...")
        start = time.monotonic()

        # Resolve reporter from DI container
        reporter = None
        try:
            from nextsploit.core.container import container
            reporter = container.resolve("reporter")
        except Exception:
            log_warning("RuleExecutionPhase: reporter not found in container — findings will not be persisted.")
            return

        # Load all rules
        loader = RuleLoader()
        all_rules = loader.load_all(RULES_DIR)
        if not all_rules:
            log_info("Rule Engine: no rules found. Skipping phase.")
            return

        # Filter by target profile constraints
        rule_filter = RuleFilter()
        eligible_rules = rule_filter.filter(all_rules, context)
        if not eligible_rules:
            log_info("Rule Engine: no eligible rules for this target profile.")
            return

        # Execute rules
        runner = RuleRunner(context=context, reporter=reporter)
        stats = runner.execute(eligible_rules)

        duration = time.monotonic() - start
        log_info(
            f"[+] Rule Execution Phase completed. "
            f"Executed={stats['executed']}, Matched={stats['matched']}, "
            f"Errors={stats['errors']}, Duration={duration:.2f}s"
        )
