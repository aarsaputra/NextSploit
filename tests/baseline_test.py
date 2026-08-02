"""
tests/baseline_test.py — Baseline Test Suite for NextSploit v4.
Starts a mock Next.js server in a background thread to verify target profile,
recon, and fingerprint phases.
"""

import sys
import os
import unittest
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests

# Add root folder to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nextsploit.core.config import ScanConfig
from nextsploit.core.context import ScanContext
from nextsploit.pipeline.pipeline import ScanPipeline
from nextsploit.phases.validation import TargetValidationPhase
from nextsploit.phases.recon import ReconPhase
from nextsploit.phases.fingerprint import FingerprintPhase
from nextsploit.phases.active import PluginExecutionPhase
from nextsploit.services.plugin_loader import check_version_constraint
from nextsploit.services.policy import PolicyEngine


class MockNextJSHandler(BaseHTTPRequestHandler):
    """Mock server simulating a Next.js application endpoint."""

    def log_message(self, format, *args):
        pass  # Suppress logging console output during tests

    def do_GET(self):
        if self.path == "/sitemap.xml":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("CF-Ray", "mocked-cloudflare-ray-id-12345")
        self.send_header("Server", "cloudflare")
        self.end_headers()

        if self.path == "/":
            # Return main page containing chunk link and window.next.version
            html = (
                "<html><head>"
                "<link rel='stylesheet' href='/_next/static/css/app/layout.css'>"
                "<script src='/_next/static/chunks/app/main.js'></script>"
                "</head><body>"
                "<script>window.next={version:'15.1.0'}</script>"
                "<h1>Welcome to Mock NextJS</h1>"
                "</body></html>"
            )
            self.wfile.write(html.encode("utf-8"))
        elif self.path == "/robots.txt":
            self.wfile.write(b"User-agent: *\nDisallow: /api/")
        elif self.path.startswith("/_next/"):
            # Mock client-side chunk files containing next version match
            chunk_content = 'window.next.version="15.1.0";console.log("main chunk");'
            self.wfile.write(chunk_content.encode("utf-8"))
        else:
            self.wfile.write(b"Not Found")



def run_mock_server(server_address, stop_event):
    httpd = HTTPServer(server_address, MockNextJSHandler)
    httpd.timeout = 0.5
    while not stop_event.is_set():
        httpd.handle_request()
    httpd.server_close()


class TestNextSploitBaseline(unittest.TestCase):
    """Baseline test suite validating Sprint 1 & 2 pipeline outputs."""

    @classmethod
    def setUpClass(cls):
        cls.server_host = "127.0.0.1"
        cls.server_port = 8089
        cls.target_url = f"http://{cls.server_host}:{cls.server_port}"
        
        cls.stop_server = threading.Event()
        cls.server_thread = threading.Thread(
            target=run_mock_server,
            args=((cls.server_host, cls.server_port), cls.stop_server),
            daemon=True
        )
        cls.server_thread.start()
        time.sleep(0.5)  # Wait for mock server to bind

    @classmethod
    def tearDownClass(cls):
        cls.stop_server.set()
        cls.server_thread.join(timeout=2)

    def test_target_profile_initialization(self):
        config = ScanConfig(target=self.target_url)
        session = requests.Session()
        context = ScanContext(self.target_url, config, session)
        
        self.assertEqual(context.profile.target_url, self.target_url)
        self.assertEqual(context.profile.framework, "Next.js")
        self.assertFalse(context.profile.server_actions)

    def test_full_pipeline_run(self):
        config = ScanConfig(target=self.target_url, timeout=2)
        session = requests.Session()
        context = ScanContext(self.target_url, config, session)
        
        pipeline = ScanPipeline()
        pipeline.registry.register(TargetValidationPhase())
        pipeline.registry.register(ReconPhase())
        pipeline.registry.register(FingerprintPhase())
        
        # Run validation, recon, and fingerprinting phases
        pipeline.run(context)
        
        profile = context.profile
        
        # Verification: Validation Phase
        self.assertEqual(profile.hostname, self.server_host)
        self.assertEqual(profile.ip, self.server_host)
        
        # Verification: Recon Phase (Cloudflare should be detected)
        self.assertEqual(profile.cdn, "Cloudflare")
        self.assertEqual(profile.waf, "Cloudflare")
        self.assertEqual(profile.robots, f"{self.target_url}/robots.txt")
        self.assertIsNone(profile.sitemap)  # /sitemap.xml returns 404 in mock
        
        # Verification: Fingerprinting Phase
        self.assertEqual(profile.framework_version, "15.1.0")
        
        # Verify headers were recorded
        self.assertIn("server", profile.headers)
        self.assertIn("cloudflare", profile.headers["server"])

    def test_version_constraints_helper(self):
        self.assertTrue(check_version_constraint("15.1.0", ">=15.0"))
        self.assertTrue(check_version_constraint("15.1.0", ">=15.0,<16.3"))
        self.assertFalse(check_version_constraint("16.4.0", ">=15.0,<16.3"))
        self.assertTrue(check_version_constraint("4.1.2", ">=4.0,<5.0"))
        self.assertFalse(check_version_constraint("3.9.9", ">=4.0"))

    def test_policy_inheritance(self):
        engine = PolicyEngine()
        # 'bugbounty' extends 'safe' and overrides active_testing to true
        policy = engine.load_policy("bugbounty")
        self.assertEqual(policy.name, "bugbounty")
        self.assertTrue(policy.is_active_testing_allowed())
        self.assertEqual(policy.get_rate_limit(), 10)
        self.assertEqual(policy.get_timeout(), 15)
        # inherited fields
        self.assertEqual(policy.get_allowed_severities(), ["low", "medium", "high", "critical"])

    def test_plugin_loader_and_isolation(self):
        # Setup mock container for reporter registration in test
        from nextsploit.core.container import container
        from nextsploit.services.reporter import ScanReporter
        if "reporter" not in container._instances:
            container.register_instance("reporter", ScanReporter())

        config = ScanConfig(target=self.target_url, policy_name="bugbounty")
        session = requests.Session()
        context = ScanContext(self.target_url, config, session)
        
        # Let's mock turbopack true so the modern sample plugin requirement resolves
        context.profile.turbopack = True
        context.profile.framework_version = "15.1.0"

        # Load and run execution phase
        phase = PluginExecutionPhase()
        phase.run(context)
        
        reporter = container.resolve("reporter")
        findings = reporter.get_findings()
        
        # We expect at least the two findings from the sample plugins to be loaded
        finding_ids = [f.id for f in findings]
        self.assertIn("next.sample.modern", finding_ids)
        self.assertIn("next.sample.legacy", finding_ids)

    def test_event_bus_and_metrics(self):
        from nextsploit.services.event_bus import EventBus
        from nextsploit.services.metrics import MetricsService
        from nextsploit.core.constants import Events

        eb = EventBus()
        metrics = MetricsService()
        metrics.attach_to_event_bus(eb)

        # Publish simulated events
        eb.publish(Events.REQUEST_SENT, {})
        eb.publish(Events.REQUEST_RECEIVED, {"status_code": 200, "duration": 0.1, "is_waf": False})
        eb.publish(Events.REQUEST_SENT, {})
        eb.publish(Events.REQUEST_RECEIVED, {"status_code": 403, "duration": 0.2, "is_waf": True})
        eb.publish(Events.REQUEST_SENT, {})
        eb.publish(Events.REQUEST_RECEIVED, {"status_code": 500, "duration": 0.3, "is_waf": False})

        stats = metrics.get_stats()
        self.assertEqual(stats["total_requests"], 3)
        self.assertEqual(stats["responses_received"], 3)
        self.assertEqual(stats["waf_blocks"], 1)
        self.assertEqual(stats["failed_requests"], 2)  # 403 and 500
        self.assertEqual(stats["average_latency_ms"], 200.0)  # (0.1+0.2+0.3)/3 = 0.2s = 200ms
        self.assertEqual(stats["success_rate_percent"], 33.33)  # 1 successful / 3 received

    def test_risk_engine_scoring(self):
        from nextsploit.services.risk import RiskEngine
        from nextsploit.services.reporter import Finding

        re = RiskEngine()
        # High base severity is 75
        f1 = Finding(id="test.f1", title="Test 1", severity="high", confidence=0.8, evidence={"exploitability": 1.0})
        score1 = re.calculate_risk_score(f1)
        # 75 * 0.8 * 1.0 = 60.0
        self.assertEqual(score1, 60.0)
        self.assertEqual(re.get_priority_level(score1), "HIGH")

        # Critical base severity is 100
        f2 = Finding(id="test.f2", title="Test 2", severity="critical", confidence=1.0, evidence={"exploitability": 0.9, "false_positive_probability": 0.1})
        score2 = re.calculate_risk_score(f2)
        # 100 * 1.0 * 0.9 * (1 - 0.1) = 81.0
        self.assertEqual(score2, 81.0)
        self.assertEqual(re.get_priority_level(score2), "CRITICAL")

    def test_circuit_breaker_functionality(self):
        from nextsploit.services.event_bus import EventBus
        from nextsploit.services.resource import ResourceManagerSession, CircuitBreakerOpenException

        eb = EventBus()
        # Set cb_threshold = 3 to trip quickly
        session = ResourceManagerSession(event_bus=eb, rate_limit=10, cb_threshold=3, cb_recovery_time=5.0)

        # Make 3 consecutive failing requests to an invalid address
        failures = 0
        for _ in range(3):
            try:
                # Trigger a failure (connection exception)
                session.get("http://invalid-subdomain-that-does-not-exist-12345.com", timeout=1)
            except Exception:
                failures += 1

        self.assertEqual(failures, 3)

        # The 4th request must raise CircuitBreakerOpenException immediately without sending traffic
        with self.assertRaises(CircuitBreakerOpenException):
            session.get("http://invalid-subdomain-that-does-not-exist-12345.com", timeout=1)

    def test_html_and_sarif_formatters(self):
        from nextsploit.services.reporter import HTMLFormatter, SARIFFormatter, Finding
        import json

        findings = [
            Finding(id="test.f1", title="Test HTML/SARIF", severity="critical", confidence=0.9, evidence={"a": 1}, request_raw="GET / HTTP/1.1", response_raw="HTTP/1.1 200 OK")
        ]
        metadata = {
            "target": "http://127.0.0.1",
            "policy": "safe",
            "duration": 5.2,
            "statistics": {"total_requests": 10, "responses_received": 10, "waf_blocks": 0, "failed_requests": 0, "average_latency_ms": 15.0, "success_rate_percent": 100.0},
            "profile": {"hostname": "localhost", "ip": "127.0.0.1", "framework_version": "15.0.0", "router": "app", "hosting": "vercel", "waf": "none"}
        }

        # Verify HTML Formatter
        hf = HTMLFormatter()
        html_out = hf.format(findings, metadata)
        self.assertIn("NextSploit", html_out)
        self.assertIn("Test HTML/SARIF", html_out)

        # Verify SARIF Formatter
        sf = SARIFFormatter()
        sarif_out = sf.format(findings, metadata)
        sarif_json = json.loads(sarif_out)
        self.assertEqual(sarif_json["version"], "2.1.0")
        self.assertEqual(len(sarif_json["runs"]), 1)
        self.assertEqual(sarif_json["runs"][0]["results"][0]["ruleId"], "test.f1")

    def test_plugin_doctor_diagnostics(self):
        from nextsploit.services.plugin_doctor import PluginDoctor
        import os

        doctor = PluginDoctor()
        # Verify modern sample plugin path
        plugin_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "plugins", "sample_modern_plugin"))
        
        if os.path.exists(plugin_path):
            res = doctor.run_check(plugin_path)
            self.assertGreaterEqual(res["health_score"], 80)
            self.assertEqual(res["checklist"]["Manifest"]["status"], "PASS")
            self.assertEqual(res["checklist"]["Import"]["status"], "PASS")

    def test_replay_engine_differential(self):
        from nextsploit.services.replay import ReplayEngine
        
        re = ReplayEngine()
        
        # Test STRICT mode diff
        orig_resp = "HTTP/1.1 200 OK\nServer: Cloudflare\n\nWelcome home"
        repl_resp = "HTTP/1.1 200 OK\nServer: Cloudflare\n\nWelcome changed"
        
        res_strict = re._compare(orig_resp, repl_resp, "STRICT")
        self.assertFalse(res_strict["is_match"])
        self.assertIn("Welcome home", res_strict["diff"]["details"])

        # Test SMART mode (Server header variations, cookies ignored)
        orig_smart = "HTTP/1.1 200 OK\nServer: Cloudflare-nginx\nDate: Sun, 02 Aug 2026\n\nWelcome home"
        repl_smart = "HTTP/1.1 200 OK\nServer: Vercel\nDate: Mon, 03 Aug 2026\n\nWelcome home"
        res_smart = re._compare(orig_smart, repl_smart, "SMART")
        self.assertTrue(res_smart["is_match"])

        # Test DIFF mode detailed structure
        res_diff = re._compare(orig_resp, repl_resp, "DIFF")
        self.assertFalse(res_diff["diff"]["status"]["changed"])
        self.assertEqual(res_diff["diff"]["status"]["original"], 200)
        self.assertIn("- Welcome home", res_diff["diff"]["body"])
        self.assertIn("+ Welcome changed", res_diff["diff"]["body"])


if __name__ == "__main__":
    unittest.main()


