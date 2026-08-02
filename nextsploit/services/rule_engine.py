"""
nextsploit/services/rule_engine.py — YAML Rule Engine orchestration layer.

Architecture:
  RuleLoader     → reads YAML files → List[Rule]
  RuleFilter     → applies version/capability constraints
  MatcherEngine  → evaluates all match conditions against a response
  RuleRunner     → sends HTTP requests, collects results
  FindingFactory → converts matched rules into Finding objects
"""

import os
import time
from typing import Any, Dict, List, Optional, Tuple

import yaml
from pydantic import ValidationError

from nextsploit.interfaces.rule import MatchBlock, MatchCondition, Rule
from nextsploit.core.logger import log_info, log_debug, log_warning, log_error
from nextsploit.services.matchers import default_registry
from nextsploit.services.template import TemplateResolver
from nextsploit.services.plugin_loader import check_version_constraint


# ────────────────────────────────────────────────
# RuleLoader
# ────────────────────────────────────────────────

class RuleLoader:
    """
    Scans a directory tree for .yaml / .yml files and parses them into Rule objects.
    Uses Pydantic for validation — invalid files are logged and skipped.
    """

    def load_all(self, rules_dir: str) -> List[Rule]:
        rules: List[Rule] = []

        if not os.path.exists(rules_dir):
            log_debug(f"Rules directory '{rules_dir}' does not exist. No rules loaded.")
            return rules

        for root, _, files in os.walk(rules_dir):
            for filename in files:
                if not filename.endswith((".yaml", ".yml")):
                    continue
                filepath = os.path.join(root, filename)
                rule = self._load_file(filepath)
                if rule:
                    rules.append(rule)

        log_info(f"Rule Engine: loaded {len(rules)} rule(s) from '{rules_dir}'.")
        return rules

    def _load_file(self, filepath: str) -> Optional[Rule]:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                log_warning(f"Rule file '{filepath}' is not a valid YAML mapping.")
                return None
            return Rule.model_validate(data)
        except ValidationError as e:
            log_warning(f"Rule validation failed for '{filepath}': {e}")
            return None
        except Exception as e:
            log_error(f"Failed to load rule file '{filepath}': {e}")
            return None


# ────────────────────────────────────────────────
# RuleFilter
# ────────────────────────────────────────────────

class RuleFilter:
    """
    Filters loaded rules against the current ScanContext.
    A rule is eligible if:
      1. Target technology matches (e.g. 'nextjs').
      2. Target framework version satisfies the rule's version constraint.
      3. All required capabilities exist in the target profile.
    """

    def filter(self, rules: List[Rule], context: Any) -> List[Rule]:
        eligible = []
        profile = getattr(context, "profile", None)

        for rule in rules:
            constraint = rule.target

            # 1. Technology check — skip if profile is missing framework version entirely
            # (heuristic: if no framework version, we can't verify version constraints)
            if constraint.version != "*" and profile:
                fw_version = getattr(profile, "framework_version", None) or ""
                if fw_version and not check_version_constraint(fw_version, constraint.version):
                    log_debug(
                        f"Rule '{rule.id}' skipped: target version "
                        f"'{fw_version}' does not match constraint '{constraint.version}'."
                    )
                    continue

            # 2. Capability requirements check
            if profile and constraint.requires:
                missing = [
                    cap for cap in constraint.requires
                    if not getattr(profile, cap, False)
                ]
                if missing:
                    log_debug(
                        f"Rule '{rule.id}' skipped: missing capabilities {missing}."
                    )
                    continue

            eligible.append(rule)

        log_info(f"Rule Engine: {len(eligible)}/{len(rules)} rule(s) eligible after filtering.")
        return eligible


# ────────────────────────────────────────────────
# MatcherEngine
# ────────────────────────────────────────────────

class MatcherEngine:
    """
    Evaluates a MatchBlock (all/any conditions) against an HTTP response.
    Returns (matched: bool, descriptions: List[str]) for evidence recording.
    """

    def evaluate(
        self,
        response: Any,
        match_block: MatchBlock,
    ) -> Tuple[bool, List[str]]:
        evidence: List[str] = []

        # ALL conditions — every one must pass
        if match_block.all:
            for condition in match_block.all:
                result = self._run_condition(response, condition)
                if not result:
                    return False, []
                evidence.append(self._describe(condition, True))

        # ANY conditions — at least one must pass
        if match_block.any:
            any_passed = False
            for condition in match_block.any:
                result = self._run_condition(response, condition)
                if result:
                    any_passed = True
                    evidence.append(self._describe(condition, True))
                    break
            if not any_passed:
                return False, []

        # If neither all nor any conditions are defined, treat as "no conditions" = no match
        if not match_block.all and not match_block.any:
            return False, []

        return True, evidence

    def _run_condition(self, response: Any, condition: MatchCondition) -> bool:
        try:
            matcher = default_registry.get(condition.type)
            return matcher.match(response, condition)
        except Exception as e:
            log_warning(f"Matcher '{condition.type}' raised exception: {e}")
            return False

    def _describe(self, condition: MatchCondition, passed: bool) -> str:
        return f"{condition.type}[{condition.operator}={condition.value}]={'PASS' if passed else 'FAIL'}"


# ────────────────────────────────────────────────
# FindingFactory
# ────────────────────────────────────────────────

class FindingFactory:
    """Converts a matched Rule into a Finding and submits it to the reporter."""

    def create(
        self,
        rule: Rule,
        request_raw: str,
        response_raw: str,
        matched_evidence: List[str],
        reporter: Any,
    ) -> None:
        from nextsploit.services.reporter import Finding

        finding = Finding(
            id=rule.id,
            title=rule.name,
            severity=rule.severity,
            confidence=rule.confidence,
            evidence={"matched_conditions": matched_evidence, "source": "rule_engine"},
            cve=rule.cve,
            cwe=rule.cwe,
            owasp=rule.owasp,
            remediation=rule.remediation,
            request_raw=request_raw,
            response_raw=response_raw,
        )

        # Add CVE references to timeline
        if rule.references:
            finding.add_timeline_event(
                "RULE_ENGINE", "INFO",
                f"CVE references: {', '.join(rule.references)}"
            )

        reporter.add_finding(finding)
        log_info(
            f"[bold red]RULE MATCH[/bold red]: {rule.id} — {rule.name} "
            f"(severity={rule.severity}, confidence={rule.confidence})"
        )


# ────────────────────────────────────────────────
# RuleRunner
# ────────────────────────────────────────────────

class RuleRunner:
    """
    Orchestrates the full rule execution pipeline for a single ScanContext:
      1. Resolve template variables per rule request.
      2. Send HTTP request via the context's ResourceManagerSession.
      3. Run MatcherEngine against the response.
      4. On match, call FindingFactory to create and register a Finding.
    Emits RULE_MATCHED / RULE_SKIPPED events to the EventBus.
    """

    def __init__(self, context: Any, reporter: Any) -> None:
        self._context = context
        self._reporter = reporter
        self._matcher = MatcherEngine()
        self._factory = FindingFactory()

    def execute(self, rules: List[Rule]) -> Dict[str, int]:
        """
        Executes all eligible rules and returns execution statistics.
        Returns: {"matched": int, "executed": int, "errors": int}
        """
        stats = {"matched": 0, "executed": 0, "errors": 0}
        resolver = TemplateResolver(self._context)
        session = self._context.session
        target_url = self._context.target_url.rstrip("/")

        # Resolve event bus from container if available
        event_bus = None
        try:
            from nextsploit.core.container import container
            event_bus = container.resolve("event_bus")
        except Exception:
            pass

        from nextsploit.core.constants import Events

        for rule in rules:
            log_debug(f"Rule Engine: executing rule '{rule.id}'...")

            for req_spec in rule.requests:
                stats["executed"] += 1

                # Resolve template variables
                resolved_path = resolver.resolve(req_spec.path)
                resolved_headers = resolver.resolve_dict(req_spec.headers)
                resolved_body = resolver.resolve(req_spec.body or "")

                url = target_url + resolved_path
                request_raw = (
                    f"{req_spec.method} {resolved_path} HTTP/1.1\n"
                    + "\n".join(f"{k}: {v}" for k, v in resolved_headers.items())
                    + ("\n\n" + resolved_body if resolved_body else "")
                )

                try:
                    start = time.monotonic()
                    response = session.request(
                        method=req_spec.method,
                        url=url,
                        headers=resolved_headers,
                        data=resolved_body or None,
                        timeout=req_spec.timeout,
                    )
                    duration = time.monotonic() - start

                    # Build response raw snapshot
                    resp_headers_str = "\n".join(
                        f"{k}: {v}" for k, v in response.headers.items()
                    )
                    response_raw = (
                        f"HTTP/1.1 {response.status_code} {response.reason}\n"
                        f"{resp_headers_str}\n\n"
                        f"{response.text[:2000]}"
                    )

                    # Evaluate match conditions
                    matched, evidence = self._matcher.evaluate(response, rule.match)

                    if matched:
                        stats["matched"] += 1
                        self._factory.create(
                            rule=rule,
                            request_raw=request_raw,
                            response_raw=response_raw,
                            matched_evidence=evidence,
                            reporter=self._reporter,
                        )
                        if event_bus:
                            event_bus.publish(Events.RULE_MATCHED, {
                                "rule_id": rule.id,
                                "duration": duration,
                                "severity": rule.severity,
                            })
                    else:
                        if event_bus:
                            event_bus.publish(Events.RULE_SKIPPED, {
                                "rule_id": rule.id,
                                "reason": "conditions_not_met",
                            })

                except Exception as e:
                    stats["errors"] += 1
                    log_warning(f"Rule '{rule.id}' request to '{url}' failed: {e}")

        return stats
