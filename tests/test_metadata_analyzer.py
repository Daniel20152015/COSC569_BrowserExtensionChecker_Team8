import io
import json
import sys
import tempfile
import unittest
import zipfile
import base64
from datetime import date
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analyzer"))

try:
    import metadata_analyzer as ma
except ModuleNotFoundError as error:
    if error.name in ("requests", "bs4"):
        raise unittest.SkipTest(f"{error.name} is not installed in this environment")
    raise

from metadata_rules import STORE_UPDATE_URL

BADGE = ("Created by the owner of the listed website. The publisher has a "
         "good record with no history of violations. Learn more.")

YOUBLOCK = f"""<html><head><title>youBlock Lite - Chrome Web Store</title>
<meta property="og:title" content="youBlock Lite - Chrome Web Store">
<meta property="og:description" content="An efficient content blocker. Blocks ads, trackers, miners, and more immediately upon installation.">
</head><body>
<nav><a href="https://myaccount.google.com/privacypolicy">Privacy Policy</a></nav>
<h1>youBlock Lite</h1><div>{BADGE}</div><a href="https://elouan.xyz">elouan.xyz</a>
<div><span>2.8</span><span>(</span><span>9 ratings</span><span>)</span></div>
<div><span>Extension</span><span>Privacy & Security</span><span>6,000 users</span></div>
<h2>Overview</h2>
<p>An efficient content blocker. Blocks ads, trackers, miners, and more immediately upon installation.</p>
<p>A simple content blocker. youBlock is a fork of uBO Lite.</p>
<h2>2.8 out of 5</h2><span>9 ratings</span>
<h2>Details</h2>
<ul><li>Version<div>2026.209.2116</div></li><li>Updated<div>February 13, 2026</div></li>
<li>Size<div>14.17MiB</div></li><li>Languages<div>2 languages</div></li>
<li>Developer<a href="https://elouan.xyz">Website</a><div>Email</div><div>help@elouan.xyz</div></li>
<li>Non-trader<div>This developer has not identified itself as a trader.</div></li></ul>
<h2>Privacy</h2><div>Manage extensions and learn how they're being used in your organization</div>
<div>The developer has disclosed that it will not collect or use your data.</div>
<h2>This developer declares that your data is</h2>
<ul><li>Not being sold to third parties, outside of the approved use cases</li>
<li>Not being used or transferred for purposes that are unrelated to the item's core functionality</li></ul>
<h2>Support</h2><footer><a href="https://myaccount.google.com/privacypolicy">Privacy Policy</a></footer>
</body></html>"""

CARGAME = f"""<html><head><title>Ultimate Car Driving Game - Chrome Web Store</title>
<meta property="og:title" content="Ultimate Car Driving Game - Chrome Web Store">
<meta property="og:description" content="Enjoy car driving simulator in a big and fascinating city.">
</head><body>
<h1>Ultimate Car Driving Game</h1><div>{BADGE}</div><a href="https://gamebol.com/">https://gamebol.com/</a>
<div>Follows recommended practices for Chrome extensions. Learn more.</div><div>Featured</div>
<div>4.4(</div><div>317 ratings</div><div>)</div>
<div>ExtensionGames500,000 users</div>
<h2>Overview</h2><p>Enjoy car driving simulator in a big and fascinating city.</p>
<p>Drive or drift around the city.</p><p>Contact with us at info@gamebol.com</p>
<h2>4.4 out of 5317 ratings</h2>
<h2>Details</h2>
<ul><li>Version<div>3.0</div></li><li>Updated<div>September 14, 2026</div></li><li>Size<div>59.16MiB</div></li>
<li>Developer<a href="https://gamebol.com/">Website</a><b>Email</b><div>info@gamebol.com</div></li>
<li>Non-trader<div>x</div></li></ul>
<h2>Privacy</h2>
<div>The developer has disclosed that it will not collect or use your data. To learn more, see the developer's
<a href="https://gamebol.com/privacy-policy/">privacy policy</a>.</div>
<h2>This developer declares that your data is</h2><ul><li>Not being sold to third parties, outside of the approved use cases</li></ul>
<h2>Support</h2></body></html>"""


ITEM_ID = "eimadpbcbfnmbkopoojfekhnkhdbieeh"
MANIFEST = {"manifest_version": 3, "name": "__MSG_name__", "version": "1.0",
            "description": "__MSG_desc__", "default_locale": "en",
            "update_url": STORE_UPDATE_URL,
            "permissions": ["storage"], "optional_permissions": ["contextMenus"]}
FILES = {
    "manifest.json": json.dumps(MANIFEST).encode(),
    "_locales/en/messages.json": json.dumps({
        "name": {"message": "Test Extension"},
        "DESC": {"message": "Makes pages dark."}}).encode(),
    "background/index.js": b"console.log('hi');\n" * 500,
    "inject/a.js": b"",
}


def signed_list(files, item_id=ITEM_ID, version="1.0", kids=("publisher", "webstore")):
    entries = [{"path": n, "root_hash": ma.treehash(io.BytesIO(d))} for n, d in files.items()]
    payload = {"content_hashes": [{"block_size": 4096, "digest": "sha256", "format": "treehash",
                                   "hash_block_size": 4096, "files": entries}],
               "item_id": item_id, "item_version": version, "protocol_version": 1}
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return json.dumps([{"description": "treehash per file", "signed_content": {
        "payload": encoded,
        "signatures": [{"header": {"kid": k}, "protected": "x", "signature": "x"} for k in kids]}}]).encode()


def make_zip(tmp, files, name="pkg.zip", signed=None, prefix=""):
    path = Path(tmp, name)
    with zipfile.ZipFile(path, "w") as z:
        for n, d in files.items():
            z.writestr(prefix + n, d)
        if signed is not None:
            z.writestr(prefix + "_metadata/verified_contents.json", signed)
    return path


class FakeResponse:

    def __init__(self, content=b"", text="", status=200):
        self.content, self.text, self.status_code = content, text, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise ma.requests.HTTPError(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size=65536):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i:i + chunk_size]


def make_crx3(zip_bytes):
    header = b"\x08\x01" * 7
    return b"Cr24" + (3).to_bytes(4, "little") + len(header).to_bytes(4, "little") + header + zip_bytes


def make_crx2(zip_bytes):
    key, sig = b"K" * 10, b"S" * 6
    return (b"Cr24" + (2).to_bytes(4, "little") + len(key).to_bytes(4, "little")
            + len(sig).to_bytes(4, "little") + key + sig + zip_bytes)


def types_of(info, expected=None):
    from metadata_rules import run_metadata_rules
    report = {"package": {
        "version": info["manifest"].get("version"),
        "update_url": info["manifest"].get("update_url"),
        "expected_id": expected,
        "signed_contents": info["signed_contents"],
        "integrity": info["integrity"]}, "source": {"listing_available": False}}
    out = run_metadata_rules(report)["analysis"]
    return ({r["type"] for r in out["review_indicators"]},
            {t["type"] for t in out["trust_indicators"]})


class TestIdentifiers(unittest.TestCase):
    def test_extension_id_extraction(self):
        eid = "looigibllgojbefbpalaagkkcenlompd"
        self.assertEqual(ma.extract_extension_id(
            f"https://chromewebstore.google.com/detail/youblock-lite/{eid}"), eid)
        self.assertEqual(ma.extract_extension_id(eid), eid)
        self.assertEqual(ma.extract_extension_id(f"{eid}.zip"), eid)
        self.assertIsNone(ma.extract_extension_id("hello"))


class TestListingParser(unittest.TestCase):
    def test_youblock_listing(self):
        d = ma.parse_listing(YOUBLOCK)
        self.assertEqual(d["name"], "youBlock Lite")
        self.assertEqual(d["category"], "Privacy & Security")
        self.assertEqual(d["users"], 6000)
        self.assertEqual((d["rating"], d["rating_count"]), (2.8, 9))
        self.assertEqual((d["version"], d["last_updated"], d["size"]),
                         ("2026.209.2116", "2026-02-13", "14.17MiB"))
        self.assertEqual(d["developer_website"], "https://elouan.xyz")
        self.assertEqual(d["developer_email"], "help@elouan.xyz")
        self.assertIsNone(d["privacy_policy_url"])
        self.assertIs(d["collects_data"], False)
        self.assertEqual(len(d["data_declarations"]), 2)
        self.assertTrue(d["long_description"].startswith("A simple content blocker"))
        self.assertTrue(d["badges"]["verified_website"])
        self.assertTrue(d["badges"]["established_publisher"])

    def test_car_game_listing_with_run_together_text(self):
        d = ma.parse_listing(CARGAME)
        self.assertEqual(d["category"], "Games")
        self.assertEqual(d["users"], 500000)
        self.assertEqual((d["rating"], d["rating_count"]), (4.4, 317))
        self.assertTrue(d["badges"]["featured"])
        self.assertEqual(d["privacy_policy_url"], "https://gamebol.com/privacy-policy/")

    def test_page_without_listing_content_raises(self):
        with self.assertRaises(ma.ListingUnavailable):
            ma.parse_listing("<html><body>Loading...</body></html>")

    def test_manual_listing_fallback_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            eid = "aomkpefnllinimbhddlfhelelngakbbn"
            Path(tmp, f"{eid}.json").write_text(json.dumps(
                {"name": "Manual Entry", "users": 10, "badges": {}}))
            self.assertEqual(ma.load_manual_listing(eid, tmp)["name"], "Manual Entry")
            self.assertIsNone(ma.load_manual_listing("b" * 32, tmp))

    def test_cross_check_listing_against_package(self):
        info = {"manifest": {"version": "3.0", "declared_permissions": ["cookies", "storage"]}}
        listing = {"version": "3.0", "long_description": "Uses storage for settings.",
                   "permission_explanations": None}
        result = ma.cross_check(listing, info)
        self.assertIs(result["version_matches"], True)
        self.assertEqual(result["permissions_not_mentioned_in_listing"], ["cookies"])


class TestTreehash(unittest.TestCase):
    def test_block_boundaries(self):
        for size in (0, 10, 4096, 4097, 4096 * 129):
            data = (bytes(range(256)) * (size // 256 + 1))[:size]
            first = ma.treehash(io.BytesIO(data))
            self.assertEqual(first, ma.treehash(io.BytesIO(data)))
            self.assertEqual(len(first), 43, size)

    def test_different_data_gives_different_hash(self):
        self.assertNotEqual(ma.treehash(io.BytesIO(b"a")), ma.treehash(io.BytesIO(b"b")))


class TestPackageAnalysis(unittest.TestCase):
    def test_intact_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            info = ma.analyze_package(make_zip(tmp, FILES, f"{ITEM_ID}.zip", signed_list(FILES)))
        self.assertEqual(info["signed_contents"]["item_id"], ITEM_ID)
        self.assertTrue(info["signed_contents"]["signed_by_webstore"])
        self.assertEqual(info["manifest"]["name"], "Test Extension")
        self.assertEqual(info["manifest"]["description"], "Makes pages dark.")
        self.assertEqual(info["integrity"]["files_matching"], 4)
        self.assertEqual(info["integrity"]["files_modified"], [])
        self.assertEqual(info["js_file_count"], 2)
        self.assertEqual(info["manifest"]["declared_permissions"], ["contextMenus", "storage"])
        review, trust = types_of(info, ITEM_ID)
        self.assertEqual(review, set())
        self.assertTrue({"signed_by_webstore", "files_match_signed_hashes"} <= trust)

    def test_modified_added_and_missing_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            signed = signed_list(FILES)
            tampered = dict(FILES, **{"background/index.js": b"evil()"})
            info = ma.analyze_package(make_zip(tmp, tampered, "t.zip", signed))
            self.assertEqual(info["integrity"]["files_modified"], ["background/index.js"])
            self.assertIn("modified_files", types_of(info)[0])

            added = dict(FILES, **{"extra.js": b"x"})
            info = ma.analyze_package(make_zip(tmp, added, "a.zip", signed))
            self.assertEqual(info["integrity"]["files_not_in_signed_list"], ["extra.js"])

            partial = {k: v for k, v in FILES.items() if k != "inject/a.js"}
            info = ma.analyze_package(make_zip(tmp, partial, "m.zip", signed))
            self.assertEqual(info["integrity"]["signed_files_missing_from_package"],
                             ["inject/a.js"])

    def test_signing_id_version_and_update_url_problems(self):
        with tempfile.TemporaryDirectory() as tmp:
            signed = signed_list(FILES)

            info = ma.analyze_package(make_zip(tmp, FILES, "v.zip", signed_list(FILES, version="9.9")))
            self.assertIn("version_mismatch", types_of(info)[0])

            info = ma.analyze_package(make_zip(tmp, FILES, "i.zip", signed))
            self.assertIn("extension_id_mismatch", types_of(info, "a" * 32)[0])

            info = ma.analyze_package(
                make_zip(tmp, FILES, "s.zip", signed_list(FILES, kids=("publisher",))))
            self.assertIn("not_signed_by_webstore", types_of(info)[0])

            info = ma.analyze_package(make_zip(tmp, FILES, "n.zip"))
            self.assertEqual(types_of(info)[0], {"no_signed_contents"})
            self.assertIsNone(info["integrity"])

            other = dict(FILES, **{"manifest.json": json.dumps(
                dict(MANIFEST, update_url="https://example.com/update.xml")).encode()})
            info = ma.analyze_package(make_zip(tmp, other, "u.zip", signed_list(other)))
            self.assertIn("non_store_update_url", types_of(info)[0])

    def test_package_layouts(self):
        with tempfile.TemporaryDirectory() as tmp:
            signed = signed_list(FILES)
            info = ma.analyze_package(make_zip(tmp, FILES, "wrapped.zip", signed, prefix="myext/"))
            self.assertEqual(info["integrity"]["files_matching"], 4)

            folder = Path(tmp, "unpacked")
            for name, data in FILES.items():
                (folder / name).parent.mkdir(parents=True, exist_ok=True)
                (folder / name).write_bytes(data)
            (folder / "_metadata").mkdir()
            (folder / "_metadata" / "verified_contents.json").write_bytes(signed)
            self.assertEqual(ma.analyze_package(folder)["integrity"]["files_matching"], 4)

            with self.assertRaises(ma.PackageError):
                ma.analyze_package(Path(tmp, "nope.zip"))

    def test_report_is_facts_only_and_json_serializable(self):
        with tempfile.TemporaryDirectory() as tmp:
            z = make_zip(tmp, FILES, f"{ITEM_ID}.zip", signed_list(FILES))
            report = ma.build_metadata_report(str(z), offline=True)
        json.dumps(report)
        self.assertEqual(report["extension"]["id"], ITEM_ID)
        self.assertEqual(report["extension"]["name"], "Test Extension")
        self.assertEqual(report["source"]["store_listing"], "package_only")
        self.assertIs(report["source"]["listing_available"], False)
        self.assertNotIn("review_indicators", report["analysis"])
        self.assertEqual(report["package"]["expected_id"], ITEM_ID)
        self.assertEqual(report["package"]["version"], "1.0")

    def test_report_from_saved_html(self):
        with tempfile.TemporaryDirectory() as tmp:
            page = Path(tmp, "page.html")
            page.write_text(YOUBLOCK, encoding="utf-8")
            report = ma.build_metadata_report(
                "https://chromewebstore.google.com/detail/youblock-lite/"
                "looigibllgojbefbpalaagkkcenlompd", html_path=page)
        self.assertEqual(report["extension"]["id"], "looigibllgojbefbpalaagkkcenlompd")
        self.assertEqual(report["source"]["store_listing"], "html_file")
        self.assertIs(report["source"]["listing_available"], True)
        self.assertEqual(report["popularity"]["users"], 6000)


class TestDownload(unittest.TestCase):
    def setUp(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("manifest.json", "{}")
        self.raw = buf.getvalue()

    def test_crx_headers(self):
        self.assertEqual(ma.crx_to_zip(make_crx3(self.raw)), self.raw)
        self.assertEqual(ma.crx_to_zip(make_crx2(self.raw)), self.raw)
        with self.assertRaises(ma.PackageError):
            ma.crx_to_zip(b"not a crx")

    def test_download_saves_reuses_and_refreshes(self):
        calls = []

        def fake_get(url, **kwargs):
            calls.append(kwargs.get("params"))
            return FakeResponse(content=make_crx3(self.raw))

        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(ma.requests, "get", fake_get):
            path = ma.download_package(ITEM_ID, tmp)
            self.assertEqual(path.name, f"{ITEM_ID}.zip")
            self.assertEqual(path.read_bytes(), self.raw)
            self.assertIn(f"id={ITEM_ID}", calls[0]["x"])
            ma.download_package(ITEM_ID, tmp)
            self.assertEqual(len(calls), 1)
            ma.download_package(ITEM_ID, tmp, refresh=True)
            self.assertEqual(len(calls), 2)

    def test_failed_downloads_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(ma.requests, "get", lambda url, **kw: FakeResponse(content=b"")):
                with self.assertRaises(ma.PackageError):
                    ma.download_package("b" * 32, tmp)
            with mock.patch.object(ma.requests, "get", lambda url, **kw: FakeResponse(status=404)):
                with self.assertRaises(ma.PackageError):
                    ma.download_package("c" * 32, tmp)

    def test_any_extension_by_url_or_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = make_zip(tmp, FILES, "src.zip", signed_list(FILES))
            crx = make_crx3(zip_path.read_bytes())

            def fake_get(url, **kwargs):
                if "update2/crx" in url:
                    return FakeResponse(content=crx)
                return FakeResponse(text=CARGAME)

            url = f"https://chromewebstore.google.com/detail/test-extension/{ITEM_ID}"
            with mock.patch.object(ma.requests, "get", fake_get):
                report = ma.build_metadata_report(url, package_dir=Path(tmp, "pk"))
                self.assertEqual(report["source"]["package"], "downloaded")
                self.assertEqual(report["package"]["integrity"]["files_matching"], 4)
                self.assertEqual(report["source"]["store_listing"], "http")
                self.assertEqual(report["popularity"]["users"], 500000)
                self.assertIsNotNone(report["manifest_crosscheck"])

                self.assertEqual(
                    ma.build_metadata_report(ITEM_ID, package_dir=Path(tmp, "pk"))["extension"]["id"],
                    ITEM_ID)

                listing_only = ma.build_metadata_report(url, download=False)
                self.assertIsNone(listing_only["package"])
                self.assertIsNone(listing_only["source"]["package"])

            def failing(url, **kwargs):
                if "update2/crx" in url:
                    return FakeResponse(status=500)
                return FakeResponse(text=CARGAME)

            with mock.patch.object(ma.requests, "get", failing):
                report = ma.build_metadata_report(url, package_dir=Path(tmp, "pk2"))
                self.assertIsNone(report["package"])
                self.assertTrue(any("download failed" in w
                                    for w in report["analysis"]["warnings"]))

            with self.assertRaises(ma.PackageError):
                ma.build_metadata_report("missing_file.zip")


if __name__ == "__main__":
    unittest.main()