# Rule Author Guide — Writing Declarative YAML Detection Rules

This guide explains how to write declarative YAML detection rules for NextSploit.

## Rule Anatomy

Rules are placed in `knowledge/rules/core/packs/nextjs/<subsystem>/<rule_id>.yaml`.

```yaml
id: CVE-2025-XXXXX
name: "Short descriptive title"
version: "1.0"

metadata:
  author: "Your Name"
  created: "2026-08-04"
  tags: [nextjs, subsystem, severity]

target:
  technology: [nextjs]
  version: ">=15.0.0,<15.2.4"
  requires: [middleware]

severity: critical # critical | high | medium | low | info
confidence: 0.9    # 0.0 to 1.0
cve: "CVE-2025-XXXXX"
cwe: "CWE-863"
owasp: "A01:2021"

references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-XXXXX

requests:
  - method: GET
    path: /
    headers:
      x-custom-header: "value"

match:
  all:
    - type: status
      operator: equals
      value: 200
    - type: header
      operator: exists
      value: x-middleware-next

remediation: |
  Clear step-by-step remediation advice for developers.
```

## Validation & Documentation

Before submitting your rule, validate it locally:
```bash
python nextsploit.py docs validate
python nextsploit.py docs generate
```
