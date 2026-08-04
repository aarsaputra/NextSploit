"""
nextsploit/services/doc_generator.py — Automated YAML Rule Documentation Generator & Validator.

Features:
  1. DocGenerator: Parses YAML rules and outputs standardized Markdown docs
     into structured directory hierarchy: `docs/detections/<technology>/<rule_id>.md`
  2. RuleValidator: Validates YAML rule integrity (valid schema, required fields,
     unique IDs across rule packs).
"""

import os
from typing import Dict, List, Tuple
from nextsploit.interfaces.rule import Rule
from nextsploit.services.rule_engine import RuleLoader
from nextsploit.core.logger import log_info, log_warning, log_error


class DocGenerator:
    """Generates Markdown documentation from YAML rules."""

    def __init__(self, output_base_dir: str = "docs/detections") -> None:
        self.output_base_dir = output_base_dir

    def generate_all(self, rules_dir: str = "knowledge/rules/core") -> List[str]:
        loader = RuleLoader()
        rules = loader.load_all(rules_dir)
        generated_files = []

        for rule in rules:
            file_path = self.generate_rule_doc(rule)
            if file_path:
                generated_files.append(file_path)

        log_info(f"DocGenerator: generated {len(generated_files)} Markdown document(s) in '{self.output_base_dir}'.")
        return generated_files

    def generate_rule_doc(self, rule: Rule) -> str:
        # Resolve target technology subdirectory (e.g. docs/detections/nextjs/)
        tech = (rule.target.technology[0] if rule.target.technology else "general").lower()
        target_dir = os.path.join(self.output_base_dir, tech)
        os.makedirs(target_dir, exist_ok=True)

        filename = f"{rule.id}.md"
        filepath = os.path.join(target_dir, filename)

        # Build paths list string
        paths = []
        for req in rule.requests:
            if req.paths:
                paths.extend(req.paths)
            else:
                paths.append(req.path)

        headers_str = ""
        for req in rule.requests:
            if req.headers:
                headers_str += "\n".join(f"  - `{k}: {v}`" for k, v in req.headers.items()) + "\n"

        refs_str = "\n".join(f"- <{ref}>" for ref in rule.references) if rule.references else "None"

        content = f"""# {rule.id} — {rule.name}

## Metadata

- **Rule ID**: `{rule.id}`
- **Severity**: `{rule.severity.upper()}`
- **Confidence**: `{rule.confidence}`
- **CVE**: `{rule.cve or 'N/A'}`
- **CWE**: `{rule.cwe or 'N/A'}`
- **OWASP Top 10**: `{rule.owasp or 'N/A'}`
- **Author**: `{rule.metadata.author}`
- **Tags**: `{', '.join(rule.metadata.tags)}`

## Execution Profile

- **Rule Type**: Declarative YAML
- **Execution Phase**: `RuleExecutionPhase` (Phase 5)
- **Detection Method**: Black-box Probing
- **Target Technology**: `{', '.join(rule.target.technology)}`
- **Target Version Constraint**: `{rule.target.version}`
- **Required Capabilities**: `{', '.join(rule.target.requires) if rule.target.requires else 'None'}`

## Probed Endpoints & Headers

### Probed Paths
{chr(10).join(f"- `{p}`" for p in set(paths))}

### Request Headers
{headers_str if headers_str else 'None'}

## Match Logic

- **Conditions**: All match conditions must evaluate to `TRUE`
{chr(10).join(f"- **{c.type}**: `{c.operator}` = `{c.value}`" for c in (rule.match.all or []))}

## Remediation

{rule.remediation}

## References

{refs_str}
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        return filepath


class RuleValidator:
    """Validates rule integrity (uniqueness, required fields, valid schema)."""

    def validate_all(self, rules_dir: str = "knowledge/rules/core") -> Tuple[bool, List[str]]:
        loader = RuleLoader()
        rules = loader.load_all(rules_dir)
        errors: List[str] = []
        seen_ids: Dict[str, str] = {}

        if not rules:
            errors.append(f"No rules found in '{rules_dir}'.")
            return False, errors

        for rule in rules:
            # Check ID uniqueness
            if rule.id in seen_ids:
                errors.append(f"Duplicate Rule ID '{rule.id}' in '{rule.name}'.")
            else:
                seen_ids[rule.id] = rule.name

            # Check mandatory metadata
            if not rule.name:
                errors.append(f"Rule '{rule.id}' missing required 'name' field.")
            if not rule.remediation:
                errors.append(f"Rule '{rule.id}' missing required 'remediation' field.")
            if not rule.requests:
                errors.append(f"Rule '{rule.id}' has no request specs defined.")

        is_valid = len(errors) == 0
        if is_valid:
            log_info(f"RuleValidator: all {len(rules)} rule(s) validated successfully.")
        else:
            log_error(f"RuleValidator: found {len(errors)} error(s).")

        return is_valid, errors
