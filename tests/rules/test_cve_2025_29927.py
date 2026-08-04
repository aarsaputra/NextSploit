"""
tests/rules/test_cve_2025_29927.py — Regression suite for CVE-2025-29927 Next.js Middleware Auth Bypass.
Tests vulnerable server match, patched server immunity, and capability filtering.
"""

import os
import sys
import unittest
import requests
from types import SimpleNamespace

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from nextsploit.services.rule_engine import RuleLoader, RuleFilter, RuleRunner
from nextsploit.services.reporter import ScanReporter
from tests.rules.servers.nextjs_vulnerable import start_vulnerable_server
from tests.rules.servers.nextjs_patched import start_patched_server

PACKS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "knowledge", "rules", "core", "packs", "nextjs")
)


class TestCVE202529927Rule(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.vuln_server, cls.vuln_port = start_vulnerable_server()
        cls.patched_server, cls.patched_port = start_patched_server()
        cls.vuln_url = f"http://127.0.0.1:{cls.vuln_port}"
        cls.patched_url = f"http://127.0.0.1:{cls.patched_port}"

        loader = RuleLoader()
        rules = loader.load_all(PACKS_DIR)
        cls.rule = next((r for r in rules if r.id == "CVE-2025-29927"), None)

    @classmethod
    def tearDownClass(cls):
        cls.vuln_server.shutdown()
        cls.patched_server.shutdown()

    def setUp(self):
        self.assertIsNotNone(self.rule, "CVE-2025-29927.yaml rule must be loaded")

    def _make_context(self, url, version="15.1.0", middleware=True):
        session = requests.Session()
        profile = SimpleNamespace(
            target_url=url,
            hostname="127.0.0.1",
            ip="127.0.0.1",
            framework="Next.js",
            framework_version=version,
            middleware=middleware,
            discovered_paths=["/dashboard", "/admin"],
        )
        return SimpleNamespace(
            target=url,
            target_url=url,
            session=session,
            profile=profile,
        )

    def test_detects_vulnerable_target(self):
        ctx = self._make_context(self.vuln_url, version="15.1.0", middleware=True)
        reporter = ScanReporter()
        runner = RuleRunner(context=ctx, reporter=reporter)

        stats = runner.execute([self.rule])

        self.assertEqual(stats["matched"], 1)
        findings = reporter.get_findings()
        self.assertEqual(len(findings), 1)

        f = findings[0]
        self.assertEqual(f.id, "CVE-2025-29927")
        self.assertEqual(f.severity.upper(), "CRITICAL")
        self.assertEqual(f.confidence, 0.95)
        self.assertEqual(f.evidence.get("extra", {}).get("source"), "rule_engine")
        self.assertEqual(f.evidence.get("extra", {}).get("detection_type"), "blackbox")

    def test_no_false_positive_on_patched_target(self):
        ctx = self._make_context(self.patched_url, version="15.2.4", middleware=True)
        reporter = ScanReporter()
        runner = RuleRunner(context=ctx, reporter=reporter)

        stats = runner.execute([self.rule])

        self.assertEqual(stats["matched"], 0)
        self.assertEqual(len(reporter.get_findings()), 0)

    def test_filter_skips_when_version_out_of_range(self):
        ctx = self._make_context(self.vuln_url, version="15.2.5", middleware=True)
        rule_filter = RuleFilter()

        eligible = rule_filter.filter([self.rule], ctx)
        self.assertEqual(len(eligible), 0)

    def test_filter_skips_when_middleware_capability_missing(self):
        ctx = self._make_context(self.vuln_url, version="15.1.0", middleware=False)
        rule_filter = RuleFilter()

        eligible = rule_filter.filter([self.rule], ctx)
        self.assertEqual(len(eligible), 0)


if __name__ == "__main__":
    unittest.main()
