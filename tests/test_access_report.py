
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analyzer"))

from access_report import build_access_report
from access_analyzer import analyze_chrome_apis, analyze_dom_access


class TestAccessAnalyzer(unittest.TestCase):

    def test_clean_extension(self):
        report = build_access_report(
            ROOT / "samples" / "clean_extension"
        )

        self.assertEqual(
            report["declared_permissions"],
            ["storage", "tabs"]
        )

        self.assertEqual(
            report["observed_api_namespaces"],
            ["storage", "tabs"]
        )

        self.assertEqual(
            report["potentially_unused_permissions"],
            []
        )

    def test_overpermissioned_extension(self):
        report = build_access_report(
            ROOT / "samples" / "overpermissioned_extension"
        )

        self.assertEqual(
            report["observed_api_namespaces"],
            ["storage"]
        )

        self.assertEqual(
            report["potentially_unused_permissions"],
            ["cookies", "history"]
        )

    def test_suspicious_extension(self):
        report = build_access_report(
            ROOT / "samples" / "suspicious_extension"
        )

        patterns = {
            finding["api_or_pattern"]
            for finding in report["dom_access"]
        }

        self.assertTrue({
            "document_cookie",
            "password_input",
            "form_access",
            "input_access",
            "page_content",
        }.issubset(patterns))

    def test_commented_chrome_api(self):
        source = "// chrome.cookies.getAll({});"

        findings = analyze_chrome_apis(
            source,
            "comment.js"
        )

        self.assertEqual(findings, [])

    def test_computed_api_access(self):
        source = 'chrome["history"].search({text: ""});'

        findings = analyze_chrome_apis(
            source,
            "computed.js"
        )

        self.assertTrue(
            any(
                finding["api_or_pattern"]
                == "chrome.history.search"
                for finding in findings
            )
        )

    def test_dom_cookie_detection(self):
        source = "const value = document.cookie;"

        findings = analyze_dom_access(
            source,
            "dom.js"
        )

        self.assertTrue(
            any(
                finding["api_or_pattern"]
                == "document_cookie"
                for finding in findings
            )
        )

    def test_no_false_positive_from_dom_comment(self):
        source = "// document.cookie"

        findings = analyze_dom_access(
            source,
            "comment.js"
        )

        self.assertEqual(findings, [])

    def test_modern_javascript_syntax(self):
        source = """
        const settings = config?.settings;
        chrome.storage.local.get("theme");
        """

        findings = analyze_chrome_apis(
            source,
            "modern.js"
        )

        self.assertTrue(
            any(
                finding["api_or_pattern"]
                == "chrome.storage.local.get"
                for finding in findings
            )
        )


if __name__ == "__main__":
    unittest.main()
