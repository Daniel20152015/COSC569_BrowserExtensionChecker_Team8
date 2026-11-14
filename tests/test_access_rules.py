"""Unit tests for Person A rules; run from repository root with unittest."""
import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analyzer"))

from access_rules import run_access_rules


class TestAccessRules(unittest.TestCase):
    @staticmethod
    def rule(report, rule_id):
        return next(
            (r for r in run_access_rules(report)["analysis"]["review_indicators"]
             if r["rule_id"] == rule_id),
            None,
        )

    def test_clean_extension_has_no_review_indicators(self):
        report = {
            "required_permissions": ["storage", "tabs"],
            "potentially_unused_permissions": [],
            "optional_permissions_without_observed_usage": [],
            "observed_without_matching_declaration": [],
            "dom_access": [],
            "analysis_complete": True,
        }
        result = run_access_rules(report)
        self.assertEqual(result["analysis"]["review_indicators"], [])

    def test_overpermissioned_extension_flags_required_permissions(self):
        report = {
            "required_permissions": ["history", "cookies", "storage"],
            "potentially_unused_permissions": ["history", "cookies"],
            "analysis_complete": True,
        }
        indicator = self.rule(report, "A001")
        self.assertEqual(indicator["severity"], "review")
        self.assertEqual([e["permission"] for e in indicator["evidence"]],
                         ["cookies", "history"])
        self.assertNotIn("malicious", indicator["type"])

    def test_optional_permissions_are_informational_only(self):
        report = {
            "required_permissions": ["storage"],
            "optional_permissions": ["history"],
            "optional_permissions_without_observed_usage": ["history"],
            "potentially_unused_permissions": [],
            "analysis_complete": True,
        }
        self.assertIsNone(self.rule(report, "A001"))
        indicator = self.rule(report, "A002")
        self.assertEqual(indicator["severity"], "informational")
        self.assertEqual(indicator["evidence"],
                         [{"permission": "history", "permission_type": "optional"}])

    def test_dom_evidence_is_preserved_but_general_inputs_are_not_flagged(self):
        dom = [
            {"type": "dom_access", "api_or_pattern": "document_cookie",
             "file": "content.js", "line": 7, "snippet": "document.cookie"},
            {"type": "dom_access", "api_or_pattern": "input_access",
             "file": "content.js", "line": 8, "snippet": "querySelector('input')"},
        ]
        rule = self.rule({"dom_access": dom}, "A003")
        self.assertEqual(rule["evidence"], [dom[0]])
        self.assertEqual(rule["severity"], "review")

    def test_unmatched_api_namespace_is_not_a_violation_claim(self):
        report = {"observed_without_matching_declaration": ["tabs"]}
        rule = self.rule(report, "A004")
        self.assertEqual(rule["severity"], "informational")
        self.assertIn("may be valid", rule["explanation"].lower())

    def test_parse_errors_make_nonuse_inconclusive(self):
        report = {
            "analysis_complete": False,
            "analysis_status": "partial",
            "required_permissions": ["history"],
            "potentially_unused_permissions": ["history"],
            "optional_permissions_without_observed_usage": ["cookies"],
            "parse_errors": [{"type": "parse_error", "file": "background.js"}],
            "inconclusive_permissions": ["history"],
        }
        out = run_access_rules(report)
        rules = {r["rule_id"] for r in out["analysis"]["review_indicators"]}
        self.assertIn("A005", rules)
        self.assertNotIn("A001", rules)
        self.assertNotIn("A002", rules)

    def test_parse_error_detected_from_all_findings(self):
        report = {"all_findings": [{"type": "parse_error", "file": "broken.js"}],
                  "potentially_unused_permissions": ["cookies"]}
        self.assertIsNotNone(self.rule(report, "A005"))
        self.assertIsNone(self.rule(report, "A001"))

    def test_preserves_source_report_and_is_idempotent(self):
        report = {
            "extension": {"name": "Example", "version": "1.0"},
            "all_findings": [],
            "analysis_complete": True,
            "required_permissions": ["history"],
            "potentially_unused_permissions": ["history"],
            "analysis": {"warnings": ["existing warning"]},
        }
        original = copy.deepcopy(report)
        first = run_access_rules(report)
        second = run_access_rules(first)
        self.assertEqual(report, original)
        self.assertEqual(first, second)
        self.assertEqual(first["analysis"]["warnings"], ["existing warning"])
        self.assertEqual(first["extension"], original["extension"])

    def test_same_shared_indicator_keys_and_order(self):
        result = run_access_rules({
            "required_permissions": ["storage"],
            "potentially_unused_permissions": ["storage"],
            "optional_permissions_without_observed_usage": ["history"],
            "dom_access": [{"type": "dom_access", "api_or_pattern": "form_access"}],
            "observed_without_matching_declaration": ["tabs"],
            "analysis_complete": False,
        })
        # Only rules not requiring complete analysis should fire.
        self.assertEqual([x["rule_id"] for x in result["analysis"]["review_indicators"]],
                         ["A003", "A004", "A005"])
        for indicator in result["analysis"]["review_indicators"]:
            self.assertEqual(set(indicator),
                             {"rule_id", "type", "severity", "evidence", "explanation"})
            self.assertIsInstance(indicator["evidence"], list)


class TestAccessRulesIntegration(unittest.TestCase):
    """Run Person A rules against actual sample reports when Esprima is installed."""

    @staticmethod
    def _build(directory):
        try:
            from access_report import build_access_report
        except ModuleNotFoundError as error:
            if error.name == "esprima":
                raise unittest.SkipTest("Esprima is not installed in this environment")
            raise
        return run_access_rules(build_access_report(ROOT / "samples" / directory))

    def test_actual_clean_sample_has_no_review_indicators(self):
        result = self._build("clean_extension")
        self.assertEqual(result["analysis"]["review_indicators"], [])

    def test_actual_overpermissioned_sample_flags_cookies_and_history(self):
        result = self._build("overpermissioned_extension")
        indicators = result["analysis"]["review_indicators"]
        self.assertEqual([item["rule_id"] for item in indicators], ["A001"])
        self.assertEqual([x["permission"] for x in indicators[0]["evidence"]],
                         ["cookies", "history"])

    def test_actual_suspicious_sample_flags_dom_access(self):
        result = self._build("suspicious_extension")
        indicators = result["analysis"]["review_indicators"]
        ids = {item["rule_id"] for item in indicators}
        self.assertIn("A001", ids)
        self.assertIn("A003", ids)
        patterns = {e["api_or_pattern"] for item in indicators
                    if item["rule_id"] == "A003" for e in item["evidence"]}
        self.assertIn("document_cookie", patterns)
        self.assertIn("password_input", patterns)


if __name__ == "__main__":
    unittest.main()
