"""
nextsploit/interfaces/rule.py — Pydantic models for the YAML Rule schema.

Using Pydantic (not plain dataclasses) because rules are loaded from external
YAML files. Pydantic provides automatic type coercion, validation errors with
clear messages, and prevents invalid rule files from entering the engine silently.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class HTTPRequestSpec(BaseModel):
    """Describes a single HTTP request to be sent during rule execution."""
    method: str = "GET"
    path: str = "/"
    # Multi-path probing: when set, RuleRunner tries each path independently.
    # Useful for rules that probe common protected routes (/dashboard, /admin, etc.).
    paths: List[str] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    timeout: int = 10


class MatchCondition(BaseModel):
    """A single match condition evaluated against the HTTP response."""
    type: str           # "status" | "header" | "regex" | "json" | "timing"
    operator: str       # "equals" | "contains" | "exists" | "not_exists" | "regex" | "lt" | "gt"
    location: str = "body"  # "body" | "header" | "status" | "elapsed"
    value: Any = None   # The target value (int, str, list, etc.)

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        allowed = {"status", "header", "regex", "json", "timing"}
        if v not in allowed:
            raise ValueError(f"Unknown matcher type '{v}'. Allowed: {allowed}")
        return v

    @field_validator("operator")
    @classmethod
    def validate_operator(cls, v: str) -> str:
        allowed = {"equals", "contains", "exists", "not_exists", "regex", "lt", "gt"}
        if v not in allowed:
            raise ValueError(f"Unknown operator '{v}'. Allowed: {allowed}")
        return v


class MatchBlock(BaseModel):
    """The match block in a rule — supports 'all' (AND) and 'any' (OR) conditions."""
    all: List[MatchCondition] = Field(default_factory=list)
    any: List[MatchCondition] = Field(default_factory=list)


class TargetConstraint(BaseModel):
    """Constraints that must be satisfied before the rule is executed."""
    technology: List[str] = Field(default_factory=lambda: ["nextjs"])
    version: str = "*"              # Semver constraint, e.g. ">=15.0,<15.2.4"
    requires: List[str] = Field(default_factory=list)  # TargetProfile capability keys


class RuleMetadata(BaseModel):
    """Optional metadata block for authoring and classification."""
    author: str = "NextSploit Team"
    created: str = ""
    tags: List[str] = Field(default_factory=list)


class Rule(BaseModel):
    """
    Complete validated representation of a YAML detection rule.
    Loaded by RuleLoader from a .yaml file in knowledge/rules/.
    """
    id: str
    name: str
    version: str = "1.0"

    metadata: RuleMetadata = Field(default_factory=RuleMetadata)

    # Severity & classification
    severity: str = "medium"
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    cve: str = ""
    cwe: str = ""
    owasp: str = ""
    references: List[str] = Field(default_factory=list)

    # Target fingerprint constraints
    target: TargetConstraint = Field(default_factory=TargetConstraint)

    # HTTP request(s) to execute
    requests: List[HTTPRequestSpec] = Field(default_factory=list)

    # Match conditions
    match: MatchBlock = Field(default_factory=MatchBlock)

    # Remediation text
    remediation: str = ""

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"critical", "high", "medium", "low", "info"}
        v = v.lower()
        if v not in allowed:
            raise ValueError(f"Unknown severity '{v}'. Allowed: {allowed}")
        return v
