import base64
import io
import json
import tempfile
import zipfile
from datetime import date, timedelta
from pathlib import Path

import metadata_analyzer as ma

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


def check(label, condition):
    print(("PASS  " if condition else "FAIL  ") + label)
    assert condition, label


def test_ids():
    eid = "looigibllgojbefbpalaagkkcenlompd"
    check("id from store url", ma.extract_extension_id(
        f"https://chromewebstore.google.com/detail/youblock-lite/{eid}") == eid)
    check("id from bare id", ma.extract_extension_id(eid) == eid)
    check("id from zip name", ma.extract_extension_id(f"{eid}.zip") == eid)
    check("no id returns None", ma.extract_extension_id("hello") is None)


def test_youblock():
    d = ma.parse_listing(YOUBLOCK)
    check("youblock name", d["name"] == "youBlock Lite")
    check("youblock category", d["category"] == "Privacy & Security")
    check("youblock users", d["users"] == 6000)
    check("youblock rating", d["rating"] == 2.8 and d["rating_count"] == 9)
    check("youblock version/updated/size",
          (d["version"], d["last_updated"], d["size"]) ==
          ("2026.209.2116", "2026-02-13", "14.17MiB"))
    check("youblock website + email",
          d["developer_website"] == "https://elouan.xyz"
          and d["developer_email"] == "help@elouan.xyz")
    check("youblock no privacy policy link", d["privacy_policy_url"] is None)
    check("youblock does not collect data", d["collects_data"] is False)
    check("youblock declarations", len(d["data_declarations"]) == 2)
    check("youblock long description trimmed",
          d["long_description"].startswith("A simple content blocker"))
    risks, trust = ma.listing_indicators(d)
    types = {r["type"] for r in risks}
    check("youblock indicators", {"no_privacy_policy", "few_ratings", "low_rating"} <= types)
    check("youblock indicator shape", all(
        set(r) == {"rule_id", "type", "severity", "evidence", "explanation"} for r in risks))
    check("youblock trust", {"verified_website", "good_publisher_record"} <= {t["type"] for t in trust})


def test_cargame():
    d = ma.parse_listing(CARGAME)
    check("car category (run-together text)", d["category"] == "Games")
    check("car users", d["users"] == 500000)
    check("car rating", d["rating"] == 4.4 and d["rating_count"] == 317)
    check("car featured badge", d["badges"]["featured"] is True)
    check("car policy url", d["privacy_policy_url"] == "https://gamebol.com/privacy-policy/")
    risks, trust = ma.listing_indicators(d)
    check("car has no review indicators", risks == [])
    check("car trust indicators", {"featured", "widely_used"} <= {t["type"] for t in trust})


def test_stale_and_crosscheck():
    old = (date.today() - timedelta(days=900)).isoformat()
    risks, _ = ma.listing_indicators({"last_updated": old, "badges": {},
                                      "privacy_policy_url": "x", "developer_website": "x",
                                      "data_disclosure": "x"})
    check("stale indicator", [r["type"] for r in risks] == ["stale_listing"])

    info = {"manifest": {"version": "3.0", "declared_permissions": ["cookies", "storage"]}}
    listing = {"version": "3.0", "long_description": "Uses storage for settings.",
               "permission_explanations": None}
    result = ma.cross_check(listing, info)
    check("version matches", result["version_matches"] is True)
    check("unmentioned permission found",
          result["permissions_not_mentioned_in_listing"] == ["cookies"])


ITEM_ID = "eimadpbcbfnmbkopoojfekhnkhdbieeh"
MANIFEST = {"manifest_version": 3, "name": "__MSG_name__", "version": "1.0",
            "description": "__MSG_desc__", "default_locale": "en",
            "update_url": ma.STORE_UPDATE_URL,
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


def types_of(info, expected=None):
    review, trust = ma.package_indicators(info, expected)
    return {r["type"] for r in review}, {t["type"] for t in trust}


def test_treehash_multiblock():
    for size in (0, 10, 4096, 4097, 4096 * 129):
        data = bytes(range(256)) * (size // 256 + 1)
        data = data[:size]
        a = ma.treehash(io.BytesIO(data))
        b = ma.treehash(io.BytesIO(data))
        check(f"treehash deterministic ({size} bytes)", a == b and len(a) == 43)
    check("treehash differs when data differs",
          ma.treehash(io.BytesIO(b"a")) != ma.treehash(io.BytesIO(b"b")))


def test_package_intact():
    with tempfile.TemporaryDirectory() as tmp:
        z = make_zip(tmp, FILES, f"{ITEM_ID}.zip", signed_list(FILES))
        info = ma.analyze_package(z)
        check("package id/version from signed list",
              info["signed_contents"]["item_id"] == ITEM_ID
              and info["signed_contents"]["signed_by_webstore"] is True)
        check("package placeholders resolved (case-insensitive keys)",
              info["manifest"]["name"] == "Test Extension"
              and info["manifest"]["description"] == "Makes pages dark.")
        check("package all files verified",
              info["integrity"]["files_matching"] == 4
              and not info["integrity"]["files_modified"])
        check("package js count and permissions",
              info["js_file_count"] == 2
              and info["manifest"]["declared_permissions"] == ["contextMenus", "storage"])
        review, trust = types_of(info, ITEM_ID)
        check("intact package has no review indicators", review == set())
        check("intact package trust indicators",
              {"signed_by_webstore", "files_match_signed_hashes"} <= trust)


def test_package_problems():
    with tempfile.TemporaryDirectory() as tmp:
        signed = signed_list(FILES)

        tampered = dict(FILES, **{"background/index.js": b"evil()"})
        info = ma.analyze_package(make_zip(tmp, tampered, "t.zip", signed))
        check("modified file detected",
              info["integrity"]["files_modified"] == ["background/index.js"])
        check("modified indicator", "modified_files" in types_of(info)[0])

        added = dict(FILES, **{"extra.js": b"x"})
        info = ma.analyze_package(make_zip(tmp, added, "a.zip", signed))
        check("unsigned file detected",
              info["integrity"]["files_not_in_signed_list"] == ["extra.js"])

        partial = {k: v for k, v in FILES.items() if k != "inject/a.js"}
        info = ma.analyze_package(make_zip(tmp, partial, "m.zip", signed))
        check("missing file reported as informational",
              info["integrity"]["signed_files_missing_from_package"] == ["inject/a.js"])
        review, _ = ma.package_indicators(info)
        check("missing file severity",
              [r["severity"] for r in review if r["type"] == "missing_signed_files"] == ["informational"])

        info = ma.analyze_package(make_zip(tmp, FILES, "v.zip", signed_list(FILES, version="9.9")))
        check("version mismatch indicator", "version_mismatch" in types_of(info)[0])

        info = ma.analyze_package(make_zip(tmp, FILES, "i.zip", signed))
        check("id mismatch indicator",
              "extension_id_mismatch" in types_of(info, "a" * 32)[0])

        info = ma.analyze_package(make_zip(tmp, FILES, "s.zip", signed_list(FILES, kids=("publisher",))))
        check("not signed by webstore", "not_signed_by_webstore" in types_of(info)[0])

        info = ma.analyze_package(make_zip(tmp, FILES, "n.zip"))
        review, _ = types_of(info)
        check("no signed list is informational only",
              review == {"no_signed_contents"} and info["integrity"] is None)

        other = dict(FILES, **{"manifest.json": json.dumps(
            dict(MANIFEST, update_url="https://example.com/update.xml")).encode()})
        info = ma.analyze_package(make_zip(tmp, other, "u.zip", signed_list(other)))
        check("non-store update url", "non_store_update_url" in types_of(info)[0])


def test_package_layouts():
    with tempfile.TemporaryDirectory() as tmp:
        signed = signed_list(FILES)

        info = ma.analyze_package(make_zip(tmp, FILES, "wrapped.zip", signed, prefix="myext/"))
        check("enclosing folder handled", info["integrity"]["files_matching"] == 4)

        folder = Path(tmp, "unpacked")
        for n, d in FILES.items():
            (folder / n).parent.mkdir(parents=True, exist_ok=True)
            (folder / n).write_bytes(d)
        (folder / "_metadata").mkdir()
        (folder / "_metadata" / "verified_contents.json").write_bytes(signed)
        info = ma.analyze_package(folder)
        check("unpacked folder handled", info["integrity"]["files_matching"] == 4)

        try:
            ma.analyze_package(Path(tmp, "nope.zip"))
            check("bad package raises", False)
        except ma.PackageError:
            check("bad package raises", True)


def test_package_report_offline():
    with tempfile.TemporaryDirectory() as tmp:
        z = make_zip(tmp, FILES, f"{ITEM_ID}.zip", signed_list(FILES))
        report = ma.build_metadata_report(str(z), offline=True)
        json.dumps(report)
        check("offline report from package only",
              report["extension"]["id"] == ITEM_ID
              and report["extension"]["name"] == "Test Extension"
              and report["source"]["store_listing"] == "package_only")
        check("report has rule-engine style sections",
              {"review_indicators", "trust_indicators", "limitations"} <= set(report["analysis"]))


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


def test_crx_and_download():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("manifest.json", "{}")
    raw = buf.getvalue()

    check("crx3 header stripped", ma.crx_to_zip(make_crx3(raw)) == raw)
    check("crx2 header stripped", ma.crx_to_zip(make_crx2(raw)) == raw)
    try:
        ma.crx_to_zip(b"not a crx")
        check("non-crx rejected", False)
    except ma.PackageError:
        check("non-crx rejected", True)

    calls = []
    real_get = ma.requests.get

    def fake_get(url, **kwargs):
        calls.append((url, kwargs.get("params")))
        return FakeResponse(content=make_crx3(raw))

    with tempfile.TemporaryDirectory() as tmp:
        ma.requests.get = fake_get
        try:
            path = ma.download_package(ITEM_ID, tmp)
            check("download saved as <id>.zip",
                  path.name == f"{ITEM_ID}.zip" and path.read_bytes() == raw)
            check("download asks for the right id",
                  f"id={ITEM_ID}" in calls[0][1]["x"])
            ma.download_package(ITEM_ID, tmp)
            check("saved package reused (no second download)", len(calls) == 1)
            ma.download_package(ITEM_ID, tmp, refresh=True)
            check("refresh downloads again", len(calls) == 2)

            ma.requests.get = lambda url, **kw: FakeResponse(content=b"")
            try:
                ma.download_package("b" * 32, tmp)
                check("empty download raises", False)
            except ma.PackageError:
                check("empty download raises", True)

            ma.requests.get = lambda url, **kw: FakeResponse(status=404)
            try:
                ma.download_package("c" * 32, tmp)
                check("http error raises", False)
            except ma.PackageError:
                check("http error raises", True)
        finally:
            ma.requests.get = real_get


def test_any_extension_by_url_or_id():
    with tempfile.TemporaryDirectory() as tmp:
        zip_path = make_zip(tmp, FILES, "src.zip", signed_list(FILES))
        crx = make_crx3(zip_path.read_bytes())
        real_get = ma.requests.get

        def fake_get(url, **kwargs):
            if "update2/crx" in url:
                return FakeResponse(content=crx)
            return FakeResponse(text=CARGAME)

        ma.requests.get = fake_get
        try:
            url = f"https://chromewebstore.google.com/detail/test-extension/{ITEM_ID}"
            report = ma.build_metadata_report(url, package_dir=Path(tmp, "pk"))
            check("url: package downloaded and verified",
                  report["source"]["package"] == "downloaded"
                  and report["package"]["integrity"]["files_matching"] == 4)
            check("url: listing parsed too",
                  report["source"]["store_listing"] == "http"
                  and report["popularity"]["users"] == 500000)
            check("url: crosscheck present", report["manifest_crosscheck"] is not None)

            report = ma.build_metadata_report(ITEM_ID, package_dir=Path(tmp, "pk"))
            check("bare id works", report["extension"]["id"] == ITEM_ID)

            report = ma.build_metadata_report(url, download=False)
            check("--no-download is listing only",
                  report["package"] is None and report["source"]["package"] is None)

            def failing(url, **kwargs):
                if "update2/crx" in url:
                    return FakeResponse(status=500)
                return FakeResponse(text=CARGAME)

            ma.requests.get = failing
            report = ma.build_metadata_report(url, package_dir=Path(tmp, "pk2"))
            check("failed download degrades to listing only",
                  report["package"] is None
                  and any("download failed" in w for w in report["analysis"]["warnings"]))

            try:
                ma.build_metadata_report("missing_file.zip")
                check("missing zip path raises", False)
            except ma.PackageError:
                check("missing zip path raises", True)
        finally:
            ma.requests.get = real_get


def test_failures():
    try:
        ma.parse_listing("<html><body>Loading...</body></html>")
        check("empty page raises", False)
    except ma.ListingUnavailable:
        check("empty page raises", True)

    with tempfile.TemporaryDirectory() as tmp:
        eid = "aomkpefnllinimbhddlfhelelngakbbn"
        Path(tmp, f"{eid}.json").write_text(json.dumps(
            {"name": "Manual Entry", "users": 10, "badges": {}}))
        check("manual fallback loads",
              ma.load_manual_listing(eid, tmp)["name"] == "Manual Entry")


def test_report_from_saved_html():
    with tempfile.TemporaryDirectory() as tmp:
        page = Path(tmp, "page.html")
        page.write_text(YOUBLOCK, encoding="utf-8")
        report = ma.build_metadata_report(
            "https://chromewebstore.google.com/detail/youblock-lite/looigibllgojbefbpalaagkkcenlompd",
            html_path=page)
        check("report id/source", report["extension"]["id"] == "looigibllgojbefbpalaagkkcenlompd"
              and report["source"]["store_listing"] == "html_file")
        json.dumps(report)
        check("report is JSON-serializable", True)


if __name__ == "__main__":
    for test in (test_ids, test_youblock, test_cargame, test_stale_and_crosscheck,
                 test_treehash_multiblock, test_package_intact, test_package_problems,
                 test_package_layouts, test_package_report_offline,
                 test_crx_and_download, test_any_extension_by_url_or_id,
                 test_failures, test_report_from_saved_html):
        test()
    print("\nAll tests passed.")