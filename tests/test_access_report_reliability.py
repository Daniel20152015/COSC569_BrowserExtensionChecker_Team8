"""Additional Person A reliability checks (uses built-in unittest)."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analyzer"))

import access_report


class TestAccessReportReliability(unittest.TestCase):
    def test_optional_permission_not_labeled_unused_required(self):
        manifest = {
            "name": "Optional Test",
            "version": "1.0",
            "permissions": ["storage"],
            "optional_permissions": ["history"],
        }
        findings = [{
            "type": "chrome_api",
            "api_or_pattern": "chrome.storage.local.get",
            "file": "background.js",
            "line": 1,
            "snippet": 'chrome.storage.local.get("key")',
        }]
        with patch.object(access_report, "load_manifest", return_value=manifest), \
             patch.object(access_report, "analyze_extension", return_value=findings):
            report = access_report.build_access_report("unused_path")
        self.assertTrue(report["analysis_complete"])
        self.assertEqual(report["potentially_unused_permissions"], [])
        self.assertEqual(report["optional_permissions"], ["history"])
        self.assertEqual(report["optional_permissions_without_observed_usage"], ["history"])

    def test_parse_error_makes_unobserved_permissions_inconclusive(self):
        manifest = {
            "name": "Parser Failure Test",
            "version": "1.0",
            "permissions": ["cookies", "history", "storage"],
        }
        findings = [
            {
                "type": "parse_error",
                "api_or_pattern": "javascript_parse_error",
                "file": "background.js",
                "line": 0,
                "snippet": "Unsupported syntax",
            },
            {
                "type": "chrome_api",
                "api_or_pattern": "chrome.storage.local.get",
                "file": "background.js",
                "line": 2,
                "snippet": 'chrome.storage.local.get("key")',
                "detection_method": "regex_fallback",
            },
        ]
        with patch.object(access_report, "load_manifest", return_value=manifest), \
             patch.object(access_report, "analyze_extension", return_value=findings):
            report = access_report.build_access_report("unused_path")
        self.assertFalse(report["analysis_complete"])
        self.assertEqual(report["analysis_status"], "partial")
        self.assertEqual(report["potentially_unused_permissions"], [])
        self.assertEqual(report["inconclusive_permissions"], ["cookies", "history"])
        self.assertEqual(len(report["parse_errors"]), 1)

    def test_original_clean_and_overpermissioned_samples(self):
        clean = access_report.build_access_report(ROOT / "samples" / "clean_extension")
        over = access_report.build_access_report(ROOT / "samples" / "overpermissioned_extension")
        self.assertTrue(clean["analysis_complete"])
        self.assertEqual(clean["potentially_unused_permissions"], [])
        self.assertTrue(over["analysis_complete"])
        self.assertEqual(over["potentially_unused_permissions"], ["cookies", "history"])


if __name__ == "__main__":
    unittest.main()
