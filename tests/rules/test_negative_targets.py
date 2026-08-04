"""
tests/rules/test_negative_targets.py — Regression suite testing non-Next.js and unknown targets.
Verifies that RuleFilter safely skips Next.js specific rules when scanning non-Next.js targets (e.g., Express/Django).
"""

import os
import sys
import unittest
import requests
from types import SimpleNamespace

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from nextsploit.services.rule_engine import RuleLoader, RuleFilter, RuleRunner
from nextsploit.services.reporter import ScanReporter
from tests.rules.servers.non_nextjs import start_non_nextjs_server

PACKS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "knowledge", "rules", "core", "packs", "nextjs")
)


class TestNegativeTargets(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.express_server, cls.express_port = start_non_nextjs_server()
        cls.express_url = f"http://127.0.0.1:{cls.express_port}"

        loader = RuleLoader()
        cls.rules = loader.load_all(PACKS_DIR)

    @classmethod
    def tearDownClass(cls):
        cls.express_server.shutdown()

    def _make_non_nextjs_context(self):
        session = requests.Session()
        profile = SimpleNamespace(
            target_url=self.express_url,
            hostname="127.0.0.1",
            ip="127.0.0.1",
            framework="Express",
            framework_version=None,
            middleware=False,
            discovered_paths=[],
        )
        return SimpleNamespace(
            target=self.express_url,
            target_url=self.express_url,
            session=session,
            profile=profile,
        )

    def test_rules_skipped_for_non_nextjs_target(self):
        ctx = self._make_non_nextjs_context()
        rule_filter = RuleFilter()

        eligible = rule_filter.filter(self.rules, ctx)
        # All rules in nextjs pack require middleware capability which profile lacks
        self.assertEqual(len(eligible), 0)

    def test_runner_returns_zero_matched_on_non_nextjs_target(self):
        ctx = self._make_non_nextjs_context()
        reporter = ScanReporter()
        runner = RuleRunner(context=ctx, reporter=reporter)

        # Even if forced to execute without filter, response is 404/200 Express, no match
        stats = runner.execute(self.rules)

        self.assertEqual(stats["matched"], 0)
        self.assertEqual(len(reporter.get_findings()), 0)


if __name__ == "__main__":
    unittest.main()
