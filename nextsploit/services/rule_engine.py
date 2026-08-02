"""
nextsploit/services/rule_engine.py — YAML Rule Engine orchestration layer.

Architecture:
  RuleLoader     → reads YAML files → List[Rule]
  RuleFilter     → applies version/capability constraints
  MatcherEngine  → evaluates all match conditions against a response
  RuleRunner     → sends HTTP requests, iterates paths[], collects results
  FindingFactory → converts matched rules into Finding objects with rich evidence
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
      1. Target framework version satisfies the rule's version constraint.
      2. All required capabilities exist in the target profile.
    """

    def filter(self, rules: List[Rule], context: Any) -> List[Rule]:
        eligible = []
        profile = getattr(context, "profile", None)

        for rule in rules:
            constraint = rule.target

            # 1. Version constraint check
            if constraint.version != "*" and profile:
                fw_version = getattr(profile, "framework_version", None) or ""
                if fw_version and not check_version_constraint(fw_version, constraint.version):
                    log_debug(
                        f"Rule '{rule.id}' skipped: version "
                        f"'{fw_version}' does not match '{constraint.version}'."
                    )
                    continue

            # 2. Capability requirements check
            if profile and constraint.requires:
                missing = [
                    cap for cap in constraint.requires
                    if not getattr(profile, cap, False)
                ]
                if missing:
                    log_debug(f"Rule '{rule.id}' skipped: missing capabilities {missing}.")
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
                evidence.append(self._describe(condition))

        # ANY conditions — at least one must pass
        if match_block.any:
            any_passed = False
            for condition in match_block.any:
                result = self._run_condition(response, condition)
                if result:
                    any_passed = True
                    evidence.append(self._describe(condition))
                    break
            if not any_passed:
                return False, []

        # If neither all nor any conditions are defined, no match
        if not match_block.all and not match_block.any:
            return False, []

        return True, evidence

    def _run_condition(self, response: Any, condition: MatchCondition) -> bool:
        try:
            matcher = default_registry.get(condition.type)
            return matcher.match(response, condition)
        except Exception as e:
            log_warning(f"Matcher '{condition.type}' raised: {e}")
            return False

    def _describe(self, condition: MatchCondition) -> str:
        return f"{condition.type}[{condition.operator}={condition.value}]=PASS"


# ────────────────────────────────────────────────
# FindingFactory
# ────────────────────────────────────────────────

class FindingFactory:
    """
    Converts a matched Rule into a structured Finding with rich evidence metadata
    and submits it to the reporter.

    Evidence structure produced:
      {
        "source": "rule_engine",
        "detection_type": "blackbox",
        "rule_id": "CVE-2025-29927",
        "matched_conditions": [...],
        "request": { "method", "path", "headers" },
        "response": { "status", "matched_headers", "body_snippet" }
      }
    """

    def create(
        self,
        rule: Rule,
        req_spec_method: str,
        req_spec_path: str,
        req_spec_headers: Dict[str, str],
        response: Any,
        matched_evidence: List[str],
        reporter: Any,
    ) -> None:
        from nextsploit.services.reporter import Finding

        # Build structured request snapshot
        req_headers_str = "\n".join(f"{k}: {v}" for k, v in req_spec_headers.items())
        request_raw = f"{req_spec_method} {req_spec_path} HTTP/1.1\n{req_headers_str}"

        # Build structured response snapshot
        resp_headers_str = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        response_raw = (
            f"HTTP/1.1 {response.status_code} {response.reason}\n"
            f"{resp_headers_str}\n\n"
            f"{response.text[:1500]}"
        )

        # Identify which response headers were specifically matched
        matched_header_names = [
            cond.split("[")[0]  # "header[exists=x-middleware-next]=PASS" → "header"
            for cond in matched_evidence if cond.startswith("header")
        ]

        evidence_dict = {
            "source": "rule_engine",
            "detection_type": "blackbox",
            "rule_id": rule.id,
            "matched_conditions": matched_evidence,
            "request": {
                "method": req_spec_method,
                "path": req_spec_path,
                "headers": req_spec_headers,
            },
            "response": {
                "status": response.status_code,
                "matched_headers": [
                    f"{k}: {v}" for k, v in response.headers.items()
                    if any(h in k.lower() for h in ["middleware", "next", "forwarded"])
                ],
                "body_snippet": response.text[:300] if response.text else "",
            },
        }

        finding = Finding(
            id=rule.id,
            title=rule.name,
            severity=rule.severity,
            confidence=rule.confidence,
            evidence=evidence_dict,
            cve=rule.cve,
            cwe=rule.cwe,
            owasp=rule.owasp,
            remediation=rule.remediation,
            request_raw=request_raw,
            response_raw=response_raw,
        )

        # Add references to timeline
        if rule.references:
            finding.add_timeline_event(
                "RULE_ENGINE", "INFO",
                f"References: {', '.join(rule.references)}"
            )

        reporter.add_finding(finding)
        log_info(
            f"[bold red]RULE MATCH[/bold red]: {rule.id} — {rule.name} "
            f"(severity={rule.severity}, confidence={rule.confidence}, path={req_spec_path})"
        )


# ────────────────────────────────────────────────
# RuleRunner
# ────────────────────────────────────────────────

class RuleRunner:
    """
    Full rule execution for a ScanContext:
      1. Resolve template variables per request spec.
      2. For each path in paths[] (or single path), send the HTTP request.
      3. Run MatcherEngine — stop on first match per rule (flag-and-continue).
      4. On match, call FindingFactory.
    Emits RULE_MATCHED / RULE_SKIPPED events to the EventBus.
    """

    def __init__(self, context: Any, reporter: Any) -> None:
        self._context = context
        self._reporter = reporter
        self._matcher = MatcherEngine()
        self._factory = FindingFactory()

    def execute(self, rules: List[Rule]) -> Dict[str, int]:
        """
        Executes all eligible rules. Returns execution statistics.
        """
        stats = {"matched": 0, "executed": 0, "errors": 0}
        resolver = TemplateResolver(self._context)
        session = self._context.session
        target_url = self._context.target_url.rstrip("/")

        event_bus = None
        try:
            from nextsploit.core.container import container
            event_bus = container.resolve("event_bus")
        except Exception:
            pass

        from nextsploit.core.constants import Events

        for rule in rules:
            rule_matched = False
            log_debug(f"Rule Engine: executing rule '{rule.id}'...")

            for req_spec in rule.requests:
                if rule_matched:
                    break  # One match per rule is sufficient

                # Determine paths to probe
                if req_spec.paths:
                    # Multi-path probing: resolve template variables in each path
                    probe_paths = [resolver.resolve(p) for p in req_spec.paths]
                else:
                    probe_paths = [resolver.resolve(req_spec.path)]

                resolved_headers = resolver.resolve_dict(req_spec.headers)
                resolved_body = resolver.resolve(req_spec.body or "")

                for probe_path in probe_paths:
                    if rule_matched:
                        break
                    stats["executed"] += 1
                    url = target_url + probe_path

                    try:
                        start = time.monotonic()
                        response = session.request(
                            method=req_spec.method,
                            url=url,
                            headers=resolved_headers,
                            data=resolved_body or None,
                            timeout=req_spec.timeout,
                            allow_redirects=False,  # Don't follow; detect redirects directly
                        )
                        duration = time.monotonic() - start

                        matched, evidence = self._matcher.evaluate(response, rule.match)

                        if matched:
                            stats["matched"] += 1
                            rule_matched = True
                            self._factory.create(
                                rule=rule,
                                req_spec_method=req_spec.method,
                                req_spec_path=probe_path,
                                req_spec_headers=resolved_headers,
                                response=response,
                                matched_evidence=evidence,
                                reporter=self._reporter,
                            )
                            if event_bus:
                                event_bus.publish(Events.RULE_MATCHED, {
                                    "rule_id": rule.id,
                                    "duration": duration,
                                    "severity": rule.severity,
                                    "path": probe_path,
                                })
                        else:
                            if event_bus:
                                event_bus.publish(Events.RULE_SKIPPED, {
                                    "rule_id": rule.id,
                                    "reason": "conditions_not_met",
                                    "path": probe_path,
                                })

                    except Exception as e:
                        stats["errors"] += 1
                        log_warning(f"Rule '{rule.id}' request to '{url}': {e}")

        return stats
