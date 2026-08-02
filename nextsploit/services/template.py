"""
nextsploit/services/template.py — TemplateResolver for YAML rule variable interpolation.

Resolves {{variable}} placeholders in rule request fields against the current ScanContext.
Supported variables:
  {{target.host}}       → context.profile.hostname
  {{target.url}}        → context.target_url
  {{target.ip}}         → context.profile.ip
  {{target.version}}    → context.profile.framework_version
  {{middleware_chain}}  → bypass chain string for middleware CVE rules
"""

import re
from typing import Any, Dict


# Default value map for common built-in template variables
_BUILTIN_VARIABLES: Dict[str, str] = {
    "middleware_chain": "middleware:middleware:middleware:middleware:middleware",
}


class TemplateResolver:
    """
    Resolves {{variable}} tokens in strings using values derived from ScanContext.
    Unknown variables are left as-is (no silent failure).
    """

    def __init__(self, context: Any) -> None:
        """
        Args:
            context: A ScanContext instance providing target profile information.
        """
        self._context = context
        self._variables = self._build_variable_map()

    def _build_variable_map(self) -> Dict[str, str]:
        profile = getattr(self._context, "profile", None)
        variables = dict(_BUILTIN_VARIABLES)

        if profile:
            variables.update({
                "target.host": getattr(profile, "hostname", "") or "",
                "target.ip": getattr(profile, "ip", "") or "",
                "target.version": getattr(profile, "framework_version", "") or "",
            })

        variables["target.url"] = getattr(self._context, "target_url", "") or ""
        return variables

    def resolve(self, text: str) -> str:
        """
        Replace all {{key}} tokens in text with their resolved values.
        Unrecognised tokens are preserved unchanged.
        """
        if not text or "{{" not in text:
            return text

        def replace_token(match: re.Match) -> str:
            key = match.group(1).strip()
            return self._variables.get(key, match.group(0))

        return re.sub(r"\{\{([^}]+)\}\}", replace_token, text)

    def resolve_dict(self, d: Dict[str, str]) -> Dict[str, str]:
        """Resolve all values in a dict (e.g. request headers)."""
        return {k: self.resolve(v) for k, v in d.items()}
