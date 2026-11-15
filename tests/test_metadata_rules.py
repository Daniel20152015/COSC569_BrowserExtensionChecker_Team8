import base64
import copy
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analyzer"))

from metadata_rules import (
    STORE_UPDATE_URL,
    run_cross_rules,
    run_metadata_rules,
)

ITEM_ID = "eimadpbcbfnmbkopoojfekhnkhdbieeh"


def make_report(**overrides):
    report = {
        "extension": {"id": ITEM_ID, "name": "Example"},
        "popularity": {"users": 500000, "rating": 4.6, "rating_count": 3000},
        "maintenance": {"version": "1.0", "last_updated": "2026-09-01",
                        "days_since_update": 60},
        "developer": {"website": "https://example.com"},
        "privacy": {"policy_url": "https://example.com/privacy",
                    "disclosure": "The developer has disclosed that it will not "
                                  "collect or use your data.",
                    "collects_data": False, "collected_data_types": []},
        "badges": {},
        "package": {
            "version": "1.0",
            "update_url": STORE_UPDATE_URL,
            "expected_id": ITEM_ID,
            "signed_contents": {"item_id": ITEM_ID, "item_version": "1.0",
                                "signature_keys": ["publisher", "webstore"],
                                "signed_by_webstore": True},
            "integrity": {"files_checked": 4, "files_matching": 4,
                          "files_modified": [], "files_not_in_signed_list": [],
                          "signed_files_missing_from_package": []},
        },
        "manifest_crosscheck": {"package_version": "1.0", "listing_version": "1.0",
                                "version_matches": True},
        "analysis": {"errors": [], "warnings": []},
        "source": {"store_listing": "http", "listing_available": True},
    }
    for path, value in overrides.items():
        section, _, key = path.partition("__")
        if key:
            report.setdefault(section, {})[key] = value
        else:
            report[section] = value
    return report


class TestMetadataRules(unittest.TestCase):
    @staticmethod
    def indicators(report):
        return run_metadata_rules(report)["analysis"]["review_indicators"]

    @classmethod
    def rule(cls, report, rule_id):
        return next((r for r in cls.indicators(report) if r["rule_id"] == rule_id), None)

    def test_healthy_extension_has_no_review_indicators(self):
        result = run_metadata_rules(make_report())
        self.assertEqual(result["analysis"]["review_indicators"], [])
        trust = {t["rule_id"] for t in result["analysis"]["trust_indicators"]}
        self.assertEqual(trust, {"T005", "T101", "T102"})

    def test_stale_listing_uses_days_since_update(self):
        rule = self.rule(make_report(maintenance={"days_since_update": 900,
                                                  "last_updated": "2024-01-01"}), "M001")
        self.assertEqual(rule["severity"], "review")
        self.assertEqual(rule["evidence"][0]["days"], 900)
        self.assertIsNone(self.rule(make_report(), "M001"))

    def test_stale_listing_falls_back_to_last_updated_date(self):
        rule = self.rule(make_report(maintenance={"last_updated": "2020-01-01"}), "M001")
        self.assertIsNotNone(rule)

    def test_popularity_rules(self):
        report = make_report(popularity={"users": 900, "rating": 2.8, "rating_count": 9})
        ids = {r["rule_id"] for r in self.indicators(report)}
        self.assertEqual({"M002", "M003", "M004"}, ids)
        self.assertEqual(self.rule(report, "M004")["evidence"], [{"rating": 2.8}])

    def test_thresholds_are_exclusive(self):
        report = make_report(popularity={"users": 1000, "rating": 3.5, "rating_count": 20})
        self.assertEqual(self.indicators(report), [])

    def test_missing_numbers_are_not_flagged(self):
        report = make_report(popularity={"users": None, "rating": None, "rating_count": None})
        self.assertEqual(self.indicators(report), [])

    def test_privacy_and_developer_rules(self):
        report = make_report(
            privacy={"policy_url": None, "disclosure": None, "collects_data": None},
            developer={"website": None})
        ids = {r["rule_id"] for r in self.indicators(report)}
        self.assertEqual({"M005", "M006", "M007"}, ids)

    def test_data_collection_is_informational_only(self):
        report = make_report(privacy={
            "policy_url": "https://example.com/p", "disclosure": "The developer has ...",
            "collects_data": True, "collected_data_types": ["Website content"]})
        rule = self.rule(report, "M008")
        self.assertEqual(rule["severity"], "informational")
        self.assertEqual(rule["evidence"], [{"collected_data_types": ["Website content"]}])

    def test_store_version_difference_is_informational(self):
        report = make_report(manifest_crosscheck={
            "package_version": "1.0", "listing_version": "1.1", "version_matches": False})
        rule = self.rule(report, "M009")
        self.assertEqual(rule["severity"], "informational")

    def test_listing_rules_skipped_when_no_listing_was_read(self):
        report = make_report(
            popularity={"users": None}, privacy={}, developer={}, maintenance={},
            source={"store_listing": "package_only", "listing_available": False})
        ids = {r["rule_id"] for r in self.indicators(report)}
        self.assertFalse(ids & {f"M00{i}" for i in range(1, 10)})

    def test_older_reports_without_listing_flag_use_store_listing_source(self):
        report = make_report(privacy={}, source={"store_listing": "http"})
        self.assertIsNotNone(self.rule(report, "M005"))
        report = make_report(privacy={}, source={"store_listing": "package_only"})
        self.assertIsNone(self.rule(report, "M005"))

    def test_listing_trust_indicators(self):
        report = make_report(badges={"featured": True, "established_publisher": True,
                                     "verified_website": True,
                                     "recommended_practices": True})
        trust = {t["rule_id"] for t in run_metadata_rules(report)["analysis"]["trust_indicators"]}
        self.assertTrue({"T001", "T002", "T003", "T004", "T005"} <= trust)

    def test_missing_signed_contents_is_informational_not_a_warning_sign(self):
        report = make_report(package={"version": "1.0", "update_url": None,
                                      "signed_contents": None, "integrity": None})
        rule = self.rule(report, "M101")
        self.assertEqual(rule["severity"], "informational")
        self.assertIn("unpacked", rule["explanation"])

    def test_not_signed_by_webstore(self):
        report = make_report()
        report["package"]["signed_contents"]["signed_by_webstore"] = False
        report["package"]["signed_contents"]["signature_keys"] = ["publisher"]
        self.assertEqual(self.rule(report, "M102")["severity"], "review")

    def test_extension_id_and_version_mismatches(self):
        report = make_report()
        report["package"]["expected_id"] = "a" * 32
        report["package"]["version"] = "2.0"
        ids = {r["rule_id"] for r in self.indicators(report)}
        self.assertTrue({"M103", "M104"} <= ids)

    def test_file_integrity_rules(self):
        report = make_report()
        report["package"]["integrity"] = {
            "files_checked": 3, "files_matching": 2,
            "files_modified": ["background/index.js"],
            "files_not_in_signed_list": ["extra.js"],
            "signed_files_missing_from_package": ["ui/a.js"]}
        by_id = {r["rule_id"]: r for r in self.indicators(report)}
        self.assertEqual(by_id["M105"]["evidence"], ["background/index.js"])
        self.assertEqual(by_id["M105"]["severity"], "review")
        self.assertEqual(by_id["M106"]["evidence"], ["extra.js"])
        self.assertEqual(by_id["M107"]["severity"], "informational")
        trust = {t["rule_id"] for t in run_metadata_rules(report)["analysis"]["trust_indicators"]}
        self.assertNotIn("T102", trust)

    def test_update_url(self):
        self.assertIsNone(self.rule(make_report(), "M108"))
        report = make_report()
        report["package"]["update_url"] = "https://example.com/update.xml"
        rule = self.rule(report, "M108")
        self.assertEqual(rule["evidence"], [{"update_url": "https://example.com/update.xml"}])
        report["package"]["update_url"] = STORE_UPDATE_URL + "/"
        self.assertIsNone(self.rule(report, "M108"))

    def test_package_only_report_has_no_listing_findings(self):
        report = make_report(source={"store_listing": "package_only",
                                     "listing_available": False})
        ids = {t["rule_id"] for t in run_metadata_rules(report)["analysis"]["trust_indicators"]}
        self.assertEqual(ids, {"T101", "T102"})

    def test_preserves_source_report_and_is_idempotent(self):
        report = make_report(maintenance={"days_since_update": 900})
        report["analysis"]["warnings"] = ["existing warning"]
        original = copy.deepcopy(report)
        first = run_metadata_rules(report)
        second = run_metadata_rules(first)
        self.assertEqual(report, original)
        self.assertEqual(first, second)
        self.assertEqual(first["analysis"]["warnings"], ["existing warning"])
        self.assertEqual(first["extension"], original["extension"])

    def test_same_shared_indicator_keys_and_order(self):
        report = make_report(
            popularity={"users": 5, "rating": 1.0, "rating_count": 2},
            privacy={}, developer={})
        report["package"]["update_url"] = "https://example.com/u.xml"
        result = run_metadata_rules(report)
        ids = [x["rule_id"] for x in result["analysis"]["review_indicators"]]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(ids, ["M002", "M003", "M004", "M005", "M006", "M007", "M108"])
        for indicator in result["analysis"]["review_indicators"]:
            self.assertEqual(set(indicator),
                             {"rule_id", "type", "severity", "evidence", "explanation"})
            self.assertIsInstance(indicator["evidence"], list)
            self.assertNotIn("malicious", indicator["type"])

    def test_limitations_are_added_without_duplicates(self):
        report = make_report()
        report["analysis"]["limitations"] = ["existing limitation"]
        once = run_metadata_rules(report)
        twice = run_metadata_rules(once)
        self.assertEqual(once["analysis"]["limitations"], twice["analysis"]["limitations"])
        self.assertEqual(once["analysis"]["limitations"][0], "existing limitation")

    def test_tolerates_malformed_sections(self):
        result = run_metadata_rules({"popularity": "bad", "package": [], "privacy": None,
                                     "source": {"store_listing": "http"}})
        self.assertIn("review_indicators", result["analysis"])

    def test_rejects_non_dictionary(self):
        with self.assertRaises(TypeError):
            run_metadata_rules([])


class TestCrossRules(unittest.TestCase):
    MANIFEST = {
        "permissions": {"sensitive_capabilities": [{"permission": "cookies"}]},
        "analysis": {"review_indicators": [
            {"rule_id": "R001", "type": "broad_host_access"}]},
    }

    def weak_metadata(self, **overrides):
        base = {"popularity": {"users": 50, "rating": 4.0, "rating_count": 3},
                "privacy": {}, "developer": {"website": "x"},
                "maintenance": {"days_since_update": 10},
                "source": {"store_listing": "http", "listing_available": True}}
        base.update(overrides)
        return base

    def test_broad_access_with_weak_trust_signals(self):
        result = run_cross_rules(self.MANIFEST, self.weak_metadata())
        rule = next(r for r in result if r["rule_id"] == "C001")
        self.assertEqual(rule["severity"], "review")
        self.assertEqual(rule["evidence"][0]["manifest_indicators"], ["broad_host_access"])
        self.assertIn("low_user_count", rule["evidence"][0]["metadata_indicators"])

    def test_one_weak_signal_is_not_enough(self):
        metadata = self.weak_metadata(popularity={"users": 5000, "rating": 4.5,
                                                  "rating_count": 500},
                                      privacy={"policy_url": "x", "disclosure": "x"})
        metadata["maintenance"] = {"days_since_update": 900}
        self.assertEqual([r for r in run_cross_rules(self.MANIFEST, metadata)
                          if r["rule_id"] == "C001"], [])

    def test_sensitive_permissions_without_privacy_information(self):
        result = run_cross_rules(self.MANIFEST, self.weak_metadata())
        rule = next(r for r in result if r["rule_id"] == "C002")
        self.assertEqual(rule["evidence"][0]["sensitive_permissions"], ["cookies"])

    def test_no_cross_findings_for_a_healthy_extension(self):
        self.assertEqual(run_cross_rules(self.MANIFEST, make_report()), [])

    def test_accepts_already_processed_metadata_report(self):
        processed = run_metadata_rules(self.weak_metadata())
        self.assertEqual(run_cross_rules(self.MANIFEST, processed),
                         run_cross_rules(self.MANIFEST, self.weak_metadata()))

    def test_does_not_change_inputs(self):
        manifest, metadata = copy.deepcopy(self.MANIFEST), self.weak_metadata()
        before = copy.deepcopy(metadata)
        run_cross_rules(manifest, metadata)
        self.assertEqual(manifest, self.MANIFEST)
        self.assertEqual(metadata, before)


class TestMetadataRulesIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            import metadata_analyzer as analyzer
        except ModuleNotFoundError as error:
            if error.name in ("requests", "bs4"):
                raise unittest.SkipTest(f"{error.name} is not installed in this environment")
            raise
        cls.analyzer = analyzer

    def signed_zip(self, tmp, files, version="1.0", update_url=STORE_UPDATE_URL):
        files = dict(files, **{"manifest.json": json.dumps(
            {"manifest_version": 3, "name": "Test", "version": version,
             "update_url": update_url}).encode()})
        entries = [{"path": n, "root_hash": self.analyzer.treehash(io.BytesIO(d))}
                   for n, d in files.items()]
        payload = {"content_hashes": [{"hash_block_size": 4096, "files": entries}],
                   "item_id": ITEM_ID, "item_version": version, "protocol_version": 1}
        encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        signed = json.dumps([{"signed_content": {"payload": encoded, "signatures": [
            {"header": {"kid": "publisher"}}, {"header": {"kid": "webstore"}}]}}])
        path = Path(tmp, f"{ITEM_ID}.zip")
        with zipfile.ZipFile(path, "w") as z:
            for name, data in files.items():
                z.writestr(name, data)
            z.writestr("_metadata/verified_contents.json", signed)
        return path

    def test_intact_package_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.signed_zip(tmp, {"background.js": b"console.log(1);"})
            report = self.analyzer.build_metadata_report(str(path), offline=True)
            result = run_metadata_rules(report)
        self.assertEqual(result["analysis"]["review_indicators"], [])
        self.assertEqual({t["rule_id"] for t in result["analysis"]["trust_indicators"]},
                         {"T101", "T102"})

    def test_tampered_package_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.signed_zip(tmp, {"background.js": b"console.log(1);"})
            tampered = Path(tmp, "tampered.zip")
            with zipfile.ZipFile(path) as src, zipfile.ZipFile(tampered, "w") as dst:
                for name in src.namelist():
                    data = src.read(name)
                    dst.writestr(name, b"stealCookies();" if name == "background.js" else data)
                dst.writestr("injected.js", b"x")
            result = run_metadata_rules(
                self.analyzer.build_metadata_report(str(tampered), offline=True))
        by_id = {r["rule_id"]: r for r in result["analysis"]["review_indicators"]}
        self.assertEqual(by_id["M105"]["evidence"], ["background.js"])
        self.assertEqual(by_id["M106"]["evidence"], ["injected.js"])

    def test_non_store_update_url_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.signed_zip(tmp, {}, update_url="https://example.com/updates.xml")
            result = run_metadata_rules(
                self.analyzer.build_metadata_report(str(path), offline=True))
        self.assertIn("M108", {r["rule_id"] for r in result["analysis"]["review_indicators"]})


if __name__ == "__main__":
    unittest.main()