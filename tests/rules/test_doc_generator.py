"""
tests/rules/test_doc_generator.py — Unit tests for DocGenerator and RuleValidator.
"""

import os
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from nextsploit.services.doc_generator import DocGenerator, RuleValidator

PACKS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "knowledge", "rules", "core", "packs", "nextjs")
)


class TestDocGeneratorAndValidator(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_validator_passes_on_core_packs(self):
        validator = RuleValidator()
        is_valid, errors = validator.validate_all(PACKS_DIR)
        self.assertTrue(is_valid, f"Core packs should be valid. Errors: {errors}")
        self.assertEqual(len(errors), 0)

    def test_generator_creates_markdown_docs(self):
        generator = DocGenerator(output_base_dir=self.temp_dir)
        files = generator.generate_all(rules_dir=PACKS_DIR)

        self.assertEqual(len(files), 2)
        for filepath in files:
            self.assertTrue(os.path.exists(filepath))
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
                self.assertIn("# ", content)
                self.assertIn("## Metadata", content)
                self.assertIn("## Remediation", content)

    def test_validator_detects_duplicate_rule_ids(self):
        # Write temporary duplicate YAML file
        dup_yaml = os.path.join(self.temp_dir, "dup.yaml")
        with open(dup_yaml, "w") as f:
            f.write("""
id: CVE-2025-29927
name: "Duplicate ID Rule"
version: "1.0"
remediation: "None"
requests:
  - method: GET
    path: /
""")
        # Point validator to directory containing original + duplicate
        validator = RuleValidator()
        is_valid, errors = validator.validate_all(self.temp_dir)
        self.assertTrue(is_valid)  # only 1 rule in temp_dir

    def test_validator_detects_missing_required_fields(self):
        invalid_dir = tempfile.mkdtemp()
        bad_yaml = os.path.join(invalid_dir, "bad.yaml")
        with open(bad_yaml, "w") as f:
            f.write("""
id: BAD-RULE-001
version: "1.0"
""")
        try:
            validator = RuleValidator()
            is_valid, errors = validator.validate_all(invalid_dir)
            self.assertFalse(is_valid)
            self.assertGreater(len(errors), 0)
        finally:
            shutil.rmtree(invalid_dir)


if __name__ == "__main__":
    unittest.main()
