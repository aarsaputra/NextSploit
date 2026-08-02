"""
nextsploit/core/context.py — ScanContext and TargetProfile definitions.
"""

import requests
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from nextsploit.core.config import ScanConfig


@dataclass
class TargetProfile:
    """
    Representation of target metadata collected during validation,
    recon, and fingerprinting phases.
    """
    target_url: str = ""
    hostname: Optional[str] = None
    ip: Optional[str] = None
    framework: str = "Next.js"
    framework_version: Optional[str] = None
    react_version: Optional[str] = None
    router: Optional[str] = None  # "app" | "pages"
    hosting: Optional[str] = None  # "Vercel" | "Netlify" | "Self-Hosted"
    cdn: Optional[str] = None
    waf: Optional[str] = None
    build_id: Optional[str] = None

    # Core Next.js feature capabilities
    middleware: bool = False
    server_actions: bool = False
    rsc: bool = False
    turbopack: bool = False
    image_optimizer: bool = False
    prefetch: bool = False
    isr: bool = False
    ppr: bool = False

    # Crawl / Passive collections
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    robots: Optional[str] = None
    sitemap: Optional[str] = None

    # Assets & evidence
    js_chunks: List[str] = field(default_factory=list)
    css_chunks: List[str] = field(default_factory=list)
    server_action_ids: List[str] = field(default_factory=list)
    capabilities: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)

    # Discovered routes (populated during recon/crawl)
    # Used by RuleEngine for realistic path probing instead of hardcoded defaults
    discovered_paths: List[str] = field(default_factory=list)



class ScanContext:
    """
    Unified runtime state representing the current scan session.
    Passed across phases and modules.
    """

    def __init__(self, target: str, config: ScanConfig, session: requests.Session):
        self.target = target
        self.config = config
        self.session = session
        
        # Core dynamic profile
        self.profile = TargetProfile(target_url=target)
        
        # State tracking
        self.current_phase: Optional[str] = None
        self.is_aborted: bool = False
        self.findings: List[Any] = []
        
        # Audit Trail log for debugging and verification
        self.audit_trail: List[Dict[str, Any]] = []

    def log_audit(self, action: str, details: str, status: str = "SUCCESS") -> None:
        """Record an action in the audit trail."""
        self.audit_trail.append({
            "action": action,
            "details": details,
            "status": status,
        })

    @property
    def target_url(self) -> str:
        """Alias for self.target — provides consistent access for Rule Engine."""
        return self.target
