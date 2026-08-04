"""
tests/rules/test_middleware_plugins.py — Regression suite for Middleware analysis plugins:
  - MiddlewareConfigPlugin
  - MiddlewareTrustPlugin
"""

import os
import sys
import unittest
import requests
from types import SimpleNamespace

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from plugins.nextjs.middleware_config import MiddlewareConfigPlugin
from plugins.nextjs.middleware_trust import MiddlewareTrustPlugin
from nextsploit.services.reporter import ScanReporter
from tests.rules.servers.nextjs_vulnerable import start_vulnerable_server
from tests.rules.servers.nextjs_patched import start_patched_server


class TestMiddlewarePlugins(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.vuln_server, cls.vuln_port = start_vulnerable_server()
        cls.patched_server, cls.patched_port = start_patched_server()
        cls.vuln_url = f"http://127.0.0.1:{cls.vuln_port}"
        cls.patched_url = f"http://127.0.0.1:{cls.patched_port}"

    @classmethod
    def tearDownClass(cls):
        cls.vuln_server.shutdown()
        cls.patched_server.shutdown()

    def _make_context(self, url, middleware=True):
        session = requests.Session()
        reporter = ScanReporter()
        profile = SimpleNamespace(
            target_url=url,
            hostname="127.0.0.1",
            ip="127.0.0.1",
            framework="Next.js",
            middleware=middleware,
            headers={"x-powered-by": "Next.js 15.1.0"},
        )
        return SimpleNamespace(
            target=url,
            target_url=url,
            session=session,
            profile=profile,
            reporter=reporter,
        )

    # ── MiddlewareConfigPlugin Tests
    def test_config_plugin_precondition(self):
        ctx = self._make_context(self.vuln_url, middleware=False)
        plugin = MiddlewareConfigPlugin()
        self.assertFalse(plugin.precondition(ctx))

    def test_config_plugin_detects_exposed_manifest(self):
        ctx = self._make_context(self.vuln_url, middleware=True)
        plugin = MiddlewareConfigPlugin()
        plugin.initialize(ctx)
        plugin.execute(ctx)

        findings = ctx.reporter.get_findings()
        self.assertGreater(len(findings), 0)
        finding_ids = [f.id for f in findings]
        self.assertIn("next.middleware.config", finding_ids)

    def test_config_plugin_patched_server_has_no_manifest_finding(self):
        ctx = self._make_context(self.patched_url, middleware=True)
        plugin = MiddlewareConfigPlugin()
        plugin.initialize(ctx)
        plugin.execute(ctx)

        # On patched server manifest is 404, only info X-Powered-By if present
        findings = [f for f in ctx.reporter.get_findings() if f.severity in ("high", "medium", "low")]
        manifest_findings = [f for f in findings if "Manifest" in f.title]
        self.assertEqual(len(manifest_findings), 0)

    # ── MiddlewareTrustPlugin Tests
    def test_trust_plugin_precondition(self):
        ctx = self._make_context(self.vuln_url, middleware=False)
        plugin = MiddlewareTrustPlugin()
        self.assertFalse(plugin.precondition(ctx))

    def test_trust_plugin_execution_graceful(self):
        ctx = self._make_context(self.patched_url, middleware=True)
        plugin = MiddlewareTrustPlugin()
        plugin.initialize(ctx)
        # Execution on patched server runs without errors
        plugin.execute(ctx)
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()
