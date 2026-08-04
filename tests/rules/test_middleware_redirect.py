"""
tests/rules/test_middleware_redirect.py — Regression suite for Next.js Middleware Open Redirect rule.
Tests redirect rule against vulnerable and patched mock servers.
"""

import os
import sys
import unittest
import requests
from types import SimpleNamespace

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from nextsploit.services.rule_engine import RuleLoader, RuleRunner
from nextsploit.services.reporter import ScanReporter
from tests.rules.servers.nextjs_vulnerable import start_vulnerable_server
from tests.rules.servers.nextjs_patched import start_patched_server

PACKS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "knowledge", "rules", "core", "packs", "nextjs")
)


class TestMiddlewareRedirectRule(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.vuln_server, cls.vuln_port = start_vulnerable_server()
        cls.patched_server, cls.patched_port = start_patched_server()
        cls.vuln_url = f"http://127.0.0.1:{cls.vuln_port}"
        cls.patched_url = f"http://127.0.0.1:{cls.patched_port}"

        loader = RuleLoader()
        rules = loader.load_all(PACKS_DIR)
        cls.rule = next((r for r in rules if r.id == "next.middleware.redirect"), None)

    @classmethod
    def tearDownClass(cls):
        cls.vuln_server.shutdown()
        cls.patched_server.shutdown()

    def setUp(self):
        self.assertIsNotNone(self.rule, "next.middleware.redirect.yaml rule must be loaded")

    def _make_context(self, url):
        session = requests.Session()
        profile = SimpleNamespace(
            target_url=url,
            hostname="127.0.0.1",
            ip="127.0.0.1",
            framework="Next.js",
            framework_version="15.1.0",
            middleware=True,
            discovered_paths=[],
        )
        return SimpleNamespace(
            target=url,
            target_url=url,
            session=session,
            profile=profile,
        )

    def test_detects_open_redirect_vulnerability(self):
        ctx = self._make_context(self.vuln_url)
        reporter = ScanReporter()
        runner = RuleRunner(context=ctx, reporter=reporter)

        stats = runner.execute([self.rule])

        self.assertEqual(stats["matched"], 1)
        findings = reporter.get_findings()
        self.assertEqual(len(findings), 1)

        f = findings[0]
        self.assertEqual(f.id, "next.middleware.redirect")
        self.assertEqual(f.severity.upper(), "HIGH")

    def test_no_finding_on_patched_redirect_server(self):
        ctx = self._make_context(self.patched_url)
        reporter = ScanReporter()
        runner = RuleRunner(context=ctx, reporter=reporter)

        stats = runner.execute([self.rule])

        self.assertEqual(stats["matched"], 0)
        self.assertEqual(len(reporter.get_findings()), 0)


if __name__ == "__main__":
    unittest.main()
