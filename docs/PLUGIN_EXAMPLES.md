# NextSploit v4 - Plugin Examples & SDK Documentation

This document explains how to build and expand the NextSploit framework by writing custom plugins.

---

## 1. Plugin Structure
Each plugin resides in its own folder under `plugins/`:
```text
plugins/
└── my_plugin/
    ├── manifest.json
    ├── plugin.py
    └── README.md
```

---

## 2. Manifest Schema (`manifest.json`)
The manifest file defines plugin metadata, compatibility, policy permissions, target capabilities requirements, and dynamic entry hooks.

```json
{
  "manifest_version": "1.0",
  "id": "next.cve.2025.29927",
  "name": "Middleware Authorization Bypass",
  "version": "1.0.0",
  "sdk_version": ">=4.0,<5.0",
  "author": "NextSploit Team",
  "description": "Checks for authorization bypass in Next.js middleware.",
  "license": "MIT",
  "entry": "plugin.py:Plugin",
  "phase": "passive",
  "severity": "critical",
  "requires": ["middleware"],
  "policies": ["safe", "bugbounty", "pentest"],
  "dependencies": ["next.fingerprint"],
  "framework": {
    "name": "nextjs",
    "version": ">=15.0.0"
  }
}
```

### Key Manifest Attributes:
- **`manifest_version`**: Must be `"1.0"` for the current specification.
- **`sdk_version`**: Framework version constraint required to execute this plugin (e.g. `">=4.0,<5.0"`).
- **`requires`**: List of target attributes required in `TargetProfile` (e.g., `middleware`, `server_actions`, `rsc`, `turbopack`).
- **`policies`**: Permissible execution profiles (e.g. `["safe", "bugbounty"]`).
- **`dependencies`**: Other plugin IDs that must run successfully before this plugin.
- **`framework`**: Target Next.js version range constraints (e.g. `{"name": "nextjs", "version": ">=15.0.0"}`).

---

## 3. Modern Plugin Example
Modern plugins implement the standard `IModule` 7-step lifecycle. They receive `PluginContext` encapsulating safe runtime APIs.

```python
# plugins/my_plugin/plugin.py
from nextsploit.interfaces.plugin_context import PluginContext
from nextsploit.services.reporter import Finding

class Plugin:
    def __init__(self):
        self.id = "next.cve.2025.29927"
        self.name = "Middleware Authorization Bypass"
        self.manifest = {}
        self.is_vulnerable = False

    def initialize(self, context: PluginContext) -> None:
        """Called before checks to set up configurations."""
        pass

    def precondition(self, context: PluginContext) -> bool:
        """Verify target prerequisites."""
        return context.profile.framework == "Next.js"

    def execute(self, context: PluginContext) -> None:
        """Perform request probes and analysis."""
        resp = context.session.get(context.profile.target_url + "/secret-path")
        if resp.status_code == 200:
            self.is_vulnerable = True

    def collect(self, context: PluginContext) -> None:
        pass

    def validate(self, context: PluginContext) -> None:
        pass

    def report(self, context: PluginContext) -> None:
        if self.is_vulnerable:
            finding = Finding(
                id=self.id,
                title="Next.js Middleware Auth Bypass discovered",
                severity="critical",
                confidence=1.0,
                evidence={"path": "/secret-path", "status": 200}
            )
            context.reporter.add_finding(finding)

    def cleanup(self, context: PluginContext) -> None:
        pass
```

---

## 4. Legacy Module Example
Older NextSploit modules exposing a simple `scan(config)` method are adapted automatically by the framework using the `LegacyAdapter` mapping.

```python
# plugins/my_legacy_plugin/plugin.py
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
    """Legacy entry point."""
    res = LegacyModuleResult("LEGACY-CVE", "Legacy Scan Title", "HIGH", "VULNERABLE")
    
    # Probing endpoint using config session
    session = config.create_session()
    r = session.get(config.target + "/api/vulnerable-endpoint")
    
    if r.status_code == 200:
        res.findings.append(LegacyFinding(
            title="Vulnerable API Exposure",
            description="Exposed vulnerable API returned status 200.",
            evidence={"url": r.url}
        ))
    return res
```
