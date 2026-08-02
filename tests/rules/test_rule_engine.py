"""
tests/rules/test_rule_engine.py — Sprint 6A: Rule Engine unit and integration tests.

Test structure:
  - Schema validation (Pydantic)
  - YAML loading (RuleLoader)
  - Matcher unit tests (each strategy in isolation)
  - TemplateResolver
  - RuleFilter (version/capability constraints)
  - Full RuleRunner integration against a live mock server
"""

import os
import sys
import json
import unittest
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# Allow running from both project root and tests/rules/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _make_mock_response(status=200, headers=None, body="hello world test"):
    """Creates a real requests.Response-like object backed by an actual HTTP request."""
    import requests
    from requests import Response
    from io import BytesIO

    resp = Response()
    resp.status_code = status
    resp.headers.update(headers or {"Content-Type": "text/html"})
    resp._content = body.encode("utf-8")
    # Simulate elapsed time
    import datetime
    resp.elapsed = datetime.timedelta(seconds=0.2)
    return resp


class _MockHandler(BaseHTTPRequestHandler):
    """Configurable mock HTTP server handler."""
    response_status = 200
    response_headers = {"Content-Type": "text/html", "x-middleware-next": "1"}
    response_body = b"hello world test"

    def do_GET(self):
        self.send_response(self.response_status)
        for k, v in self.response_headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(self.response_body)

    def log_message(self, *args):
        pass  # Suppress noisy output


def _start_mock_server(handler_class=_MockHandler, port=0):
    server = HTTPServer(("127.0.0.1", port), handler_class)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


# ─────────────────────────────────────────────────────────────
# Test Suite
# ─────────────────────────────────────────────────────────────

class TestRuleSchema(unittest.TestCase):
    """6A.1 — Rule schema Pydantic validation."""

    def test_valid_rule_loads_from_fixture(self):
        from nextsploit.services.rule_engine import RuleLoader
        loader = RuleLoader()
        rules = loader.load_all(FIXTURES_DIR)
        self.assertGreaterEqual(len(rules), 3)
        rule_ids = [r.id for r in rules]
        self.assertIn("TEST-STATUS-001", rule_ids)
        self.assertIn("TEST-HEADER-001", rule_ids)
        self.assertIn("TEST-REGEX-001", rule_ids)

    def test_rule_fields_are_typed_correctly(self):
        from nextsploit.services.rule_engine import RuleLoader
        loader = RuleLoader()
        rules = loader.load_all(FIXTURES_DIR)
        for rule in rules:
            self.assertIsInstance(rule.id, str)
            self.assertIsInstance(rule.confidence, float)
            self.assertIn(rule.severity, {"critical", "high", "medium", "low", "info"})

    def test_invalid_confidence_type_raises_validation_error(self):
        from pydantic import ValidationError
        from nextsploit.interfaces.rule import Rule
        with self.assertRaises(ValidationError):
            Rule.model_validate({
                "id": "BAD-001",
                "name": "Bad Rule",
                "confidence": "not-a-float",
                "requests": [],
            })

    def test_invalid_severity_raises_validation_error(self):
        from pydantic import ValidationError
        from nextsploit.interfaces.rule import Rule
        with self.assertRaises(ValidationError):
            Rule.model_validate({
                "id": "BAD-002",
                "name": "Bad Severity",
                "severity": "super_critical",
                "requests": [],
            })

    def test_unknown_matcher_type_raises_validation_error(self):
        from pydantic import ValidationError
        from nextsploit.interfaces.rule import MatchCondition
        with self.assertRaises(ValidationError):
            MatchCondition.model_validate({
                "type": "custom_unknown",
                "operator": "equals",
                "value": 200,
            })


class TestMatcherStrategies(unittest.TestCase):
    """6A.2 — Individual matcher strategy unit tests."""

    def _cond(self, type_, operator, value, location="body"):
        from nextsploit.interfaces.rule import MatchCondition
        return MatchCondition(type=type_, operator=operator, value=value, location=location)

    # StatusMatcher
    def test_status_equals_match(self):
        from nextsploit.services.matchers.status import StatusMatcher
        r = _make_mock_response(status=200)
        self.assertTrue(StatusMatcher().match(r, self._cond("status", "equals", 200)))

    def test_status_equals_no_match(self):
        from nextsploit.services.matchers.status import StatusMatcher
        r = _make_mock_response(status=403)
        self.assertFalse(StatusMatcher().match(r, self._cond("status", "equals", 200)))

    def test_status_lt(self):
        from nextsploit.services.matchers.status import StatusMatcher
        r = _make_mock_response(status=200)
        self.assertTrue(StatusMatcher().match(r, self._cond("status", "lt", 300)))

    # HeaderMatcher
    def test_header_exists_match(self):
        from nextsploit.services.matchers.header import HeaderMatcher
        r = _make_mock_response(headers={"x-middleware-next": "1"})
        self.assertTrue(HeaderMatcher().match(r, self._cond("header", "exists", "x-middleware-next")))

    def test_header_exists_no_match(self):
        from nextsploit.services.matchers.header import HeaderMatcher
        r = _make_mock_response(headers={})
        self.assertFalse(HeaderMatcher().match(r, self._cond("header", "exists", "x-custom-absent")))

    def test_header_not_exists(self):
        from nextsploit.services.matchers.header import HeaderMatcher
        r = _make_mock_response(headers={})
        self.assertTrue(HeaderMatcher().match(r, self._cond("header", "not_exists", "x-absent")))

    def test_header_value_equals(self):
        from nextsploit.services.matchers.header import HeaderMatcher
        from nextsploit.interfaces.rule import MatchCondition
        r = _make_mock_response(headers={"x-powered-by": "Next.js"})
        cond = MatchCondition(type="header", operator="equals",
                              value={"name": "x-powered-by", "value": "Next.js"})
        self.assertTrue(HeaderMatcher().match(r, cond))

    # RegexMatcher
    def test_regex_body_match(self):
        from nextsploit.services.matchers.regex import RegexMatcher
        r = _make_mock_response(body="This page is built with Next.js")
        self.assertTrue(RegexMatcher().match(r, self._cond("regex", "regex", r"Next\.js")))

    def test_regex_body_no_match(self):
        from nextsploit.services.matchers.regex import RegexMatcher
        r = _make_mock_response(body="Boring static page")
        self.assertFalse(RegexMatcher().match(r, self._cond("regex", "regex", r"Next\.js")))

    def test_regex_invalid_pattern_returns_false(self):
        from nextsploit.services.matchers.regex import RegexMatcher
        r = _make_mock_response(body="test")
        self.assertFalse(RegexMatcher().match(r, self._cond("regex", "regex", "[invalid")))

    # JsonMatcher
    def test_json_key_exists(self):
        from nextsploit.services.matchers.json_matcher import JsonMatcher
        from nextsploit.interfaces.rule import MatchCondition
        r = _make_mock_response(body='{"error": {"code": 403}}')
        r.headers.update({"Content-Type": "application/json"})
        import io
        r._content = b'{"error": {"code": 403}}'
        cond = MatchCondition(type="json", operator="exists", value={"key": "error.code"})
        self.assertTrue(JsonMatcher().match(r, cond))

    # TimingMatcher
    def test_timing_gt_match(self):
        from nextsploit.services.matchers.timing import TimingMatcher
        r = _make_mock_response()  # elapsed = 0.2s
        self.assertTrue(TimingMatcher().match(r, self._cond("timing", "gt", 0.1)))

    def test_timing_gt_no_match(self):
        from nextsploit.services.matchers.timing import TimingMatcher
        r = _make_mock_response()  # elapsed = 0.2s
        self.assertFalse(TimingMatcher().match(r, self._cond("timing", "gt", 5.0)))


class TestMatcherEngine(unittest.TestCase):
    """Tests MatcherEngine ALL/ANY logic."""

    def test_all_conditions_pass(self):
        from nextsploit.services.rule_engine import MatcherEngine
        from nextsploit.interfaces.rule import MatchBlock, MatchCondition
        engine = MatcherEngine()
        r = _make_mock_response(status=200, headers={"x-middleware-next": "1"})
        block = MatchBlock(all=[
            MatchCondition(type="status", operator="equals", value=200),
            MatchCondition(type="header", operator="exists", value="x-middleware-next"),
        ])
        matched, evidence = engine.evaluate(r, block)
        self.assertTrue(matched)
        self.assertEqual(len(evidence), 2)

    def test_all_conditions_one_fails(self):
        from nextsploit.services.rule_engine import MatcherEngine
        from nextsploit.interfaces.rule import MatchBlock, MatchCondition
        engine = MatcherEngine()
        r = _make_mock_response(status=403)
        block = MatchBlock(all=[
            MatchCondition(type="status", operator="equals", value=200),
            MatchCondition(type="header", operator="exists", value="x-middleware-next"),
        ])
        matched, evidence = engine.evaluate(r, block)
        self.assertFalse(matched)
        self.assertEqual(evidence, [])

    def test_any_conditions_one_passes(self):
        from nextsploit.services.rule_engine import MatcherEngine
        from nextsploit.interfaces.rule import MatchBlock, MatchCondition
        engine = MatcherEngine()
        r = _make_mock_response(status=200)
        block = MatchBlock(any=[
            MatchCondition(type="status", operator="equals", value=404),  # FAIL
            MatchCondition(type="status", operator="equals", value=200),  # PASS
        ])
        matched, evidence = engine.evaluate(r, block)
        self.assertTrue(matched)


class TestTemplateResolver(unittest.TestCase):
    """6A.2 — TemplateResolver variable substitution."""

    def _make_context(self, hostname="example.com", version="15.1.0"):
        from types import SimpleNamespace
        profile = SimpleNamespace(hostname=hostname, ip="1.2.3.4", framework_version=version)
        return SimpleNamespace(profile=profile, target_url=f"https://{hostname}/")

    def test_resolves_target_host(self):
        from nextsploit.services.template import TemplateResolver
        ctx = self._make_context()
        resolver = TemplateResolver(ctx)
        result = resolver.resolve("Host: {{target.host}}")
        self.assertEqual(result, "Host: example.com")

    def test_resolves_middleware_chain(self):
        from nextsploit.services.template import TemplateResolver
        ctx = self._make_context()
        resolver = TemplateResolver(ctx)
        result = resolver.resolve("{{middleware_chain}}")
        self.assertIn("middleware:middleware", result)

    def test_unknown_variable_preserved(self):
        from nextsploit.services.template import TemplateResolver
        ctx = self._make_context()
        resolver = TemplateResolver(ctx)
        result = resolver.resolve("{{unknown_variable}}")
        self.assertEqual(result, "{{unknown_variable}}")

    def test_resolve_dict(self):
        from nextsploit.services.template import TemplateResolver
        ctx = self._make_context(hostname="target.com")
        resolver = TemplateResolver(ctx)
        result = resolver.resolve_dict({
            "Host": "{{target.host}}",
            "X-Static": "static-value",
        })
        self.assertEqual(result["Host"], "target.com")
        self.assertEqual(result["X-Static"], "static-value")


class TestRuleFilter(unittest.TestCase):
    """6A.2 — RuleFilter version and capability constraint tests."""

    def _make_context(self, version="15.1.0", middleware=True):
        from types import SimpleNamespace
        profile = SimpleNamespace(
            framework_version=version,
            middleware=middleware,
        )
        return SimpleNamespace(profile=profile, target_url="http://127.0.0.1/")

    def test_rule_passes_when_version_matches(self):
        from nextsploit.services.rule_engine import RuleFilter, RuleLoader
        from nextsploit.interfaces.rule import Rule, TargetConstraint
        rule = Rule.model_validate({
            "id": "TEST-FILTER-001",
            "name": "Filter Test",
            "target": {"version": ">=15.0,<16.0", "requires": []},
            "requests": [],
        })
        ctx = self._make_context(version="15.1.0")
        result = RuleFilter().filter([rule], ctx)
        self.assertEqual(len(result), 1)

    def test_rule_skipped_when_version_mismatch(self):
        from nextsploit.services.rule_engine import RuleFilter
        from nextsploit.interfaces.rule import Rule
        rule = Rule.model_validate({
            "id": "TEST-FILTER-002",
            "name": "Filter Version Fail",
            "target": {"version": ">=15.0,<15.1.0", "requires": []},
            "requests": [],
        })
        ctx = self._make_context(version="15.2.0")
        result = RuleFilter().filter([rule], ctx)
        self.assertEqual(len(result), 0)

    def test_rule_skipped_when_capability_missing(self):
        from nextsploit.services.rule_engine import RuleFilter
        from nextsploit.interfaces.rule import Rule
        rule = Rule.model_validate({
            "id": "TEST-FILTER-003",
            "name": "Filter Capability Fail",
            "target": {"version": "*", "requires": ["middleware"]},
            "requests": [],
        })
        ctx = self._make_context(middleware=False)  # capability not present
        result = RuleFilter().filter([rule], ctx)
        self.assertEqual(len(result), 0)


class TestRuleRunnerIntegration(unittest.TestCase):
    """6A.5 — Full RuleRunner integration test against a live mock server."""

    @classmethod
    def setUpClass(cls):
        cls.server, cls.port = _start_mock_server()
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _make_context(self):
        import requests as req
        from types import SimpleNamespace
        profile = SimpleNamespace(
            hostname="127.0.0.1",
            ip="127.0.0.1",
            framework_version="15.1.0",
            middleware=True,
        )
        session = req.Session()
        return SimpleNamespace(
            profile=profile,
            target_url=self.base_url,
            session=session,
        )

    def test_status_rule_matches_mock_server(self):
        from nextsploit.services.rule_engine import RuleLoader, RuleFilter, RuleRunner
        from nextsploit.services.reporter import ScanReporter

        loader = RuleLoader()
        rules = loader.load_all(FIXTURES_DIR)
        status_rules = [r for r in rules if r.id == "TEST-STATUS-001"]

        reporter = ScanReporter()
        ctx = self._make_context()
        runner = RuleRunner(context=ctx, reporter=reporter)
        stats = runner.execute(status_rules)

        self.assertEqual(stats["matched"], 1)
        self.assertEqual(len(reporter.get_findings()), 1)
        self.assertEqual(reporter.get_findings()[0].id, "TEST-STATUS-001")

    def test_header_rule_matches_mock_server(self):
        from nextsploit.services.rule_engine import RuleLoader, RuleRunner
        from nextsploit.services.reporter import ScanReporter

        loader = RuleLoader()
        rules = [r for r in loader.load_all(FIXTURES_DIR) if r.id == "TEST-HEADER-001"]

        reporter = ScanReporter()
        ctx = self._make_context()
        runner = RuleRunner(context=ctx, reporter=reporter)
        stats = runner.execute(rules)

        self.assertEqual(stats["matched"], 1)

    def test_regex_rule_matches_mock_server_body(self):
        from nextsploit.services.rule_engine import RuleLoader, RuleRunner
        from nextsploit.services.reporter import ScanReporter

        loader = RuleLoader()
        rules = [r for r in loader.load_all(FIXTURES_DIR) if r.id == "TEST-REGEX-001"]

        reporter = ScanReporter()
        ctx = self._make_context()
        runner = RuleRunner(context=ctx, reporter=reporter)
        stats = runner.execute(rules)

        self.assertEqual(stats["matched"], 1)

    def test_finding_contains_matched_conditions_in_evidence(self):
        """Verifies that the Finding's evidence.extra records which conditions matched."""
        from nextsploit.services.rule_engine import RuleLoader, RuleRunner
        from nextsploit.services.reporter import ScanReporter

        loader = RuleLoader()
        rules = [r for r in loader.load_all(FIXTURES_DIR) if r.id == "TEST-STATUS-001"]

        reporter = ScanReporter()
        ctx = self._make_context()
        runner = RuleRunner(context=ctx, reporter=reporter)
        runner.execute(rules)

        findings = reporter.get_findings()
        self.assertEqual(len(findings), 1)
        evidence_extra = findings[0].evidence.get("extra", {})
        self.assertIn("matched_conditions", evidence_extra)
        self.assertGreater(len(evidence_extra["matched_conditions"]), 0)


if __name__ == "__main__":
    unittest.main()
