"""
plugins/sample_legacy_plugin/plugin.py — Sample Legacy Plugin exposing scan(config).
"""


class LegacyFinding:
    def __init__(self, title, description, evidence=None):
        self.title = title
        self.description = description
        self.evidence = evidence or {}


class LegacyModuleResult:
    def __init__(self, cve, title, severity, status):
        self.cve = cve
        self.title = title
        self.severity = severity
        self.status = status
        self.findings = []


def scan(config) -> LegacyModuleResult:
    """
    Legacy scan function signature: def scan(config) -> ModuleResult.
    """
    res = LegacyModuleResult(
        cve="LEGACY-SAMPLE",
        title="Sample Legacy Plugin Discovery",
        severity="MEDIUM",
        status="VULNERABLE"
    )
    
    # Simulate discovering a finding
    f = LegacyFinding(
        title="Legacy Plugin Working (Sample)",
        description="This was run via the LegacyAdapter to demonstrate backwards compatibility.",
        evidence={"target": config.target}
    )
    res.findings.append(f)
    return res
