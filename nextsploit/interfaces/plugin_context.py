"""
nextsploit/interfaces/plugin_context.py — Interface and class definition for PluginContext.
"""

import requests
from typing import Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from nextsploit.core.context import TargetProfile
    from nextsploit.interfaces.reporter import IReporter
    from nextsploit.core.kb import KnowledgeBase


class PluginContext:
    """
    Public context API provided to plugins.
    Encapsulates core framework components, shielding plugins from raw ScanContext internals.
    """

    def __init__(
        self,
        profile: "TargetProfile",
        reporter: "IReporter",
        session: requests.Session,
        kb: "KnowledgeBase",
        policy: Dict[str, Any]
    ):
        self.profile = profile
        self.reporter = reporter
        self.session = session
        self.kb = kb
        self.policy = policy
