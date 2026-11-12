import argparse
import base64
import hashlib
import json
import re
import sys
import time
import zipfile
from datetime import date, datetime
from pathlib import Path
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


STORE_DETAIL_URL = "https://chromewebstore.google.com/detail/"

STORE_UPDATE_URL = "https://clients2.google.com/service/update2/crx"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}

OUTPUT_DIR = Path("metadata_output")
MANUAL_DIR = Path("metadata_manual")
PACKAGE_DIR = OUTPUT_DIR / "packages"

CRX_DOWNLOAD_URL = "https://clients2.google.com/service/update2/crx"
CRX_PROD_VERSION = "140.0.0.0"
MAX_PACKAGE_BYTES = 100 * 1024 * 1024

STALE_DAYS = 548
LOW_USER_COUNT = 1000
FEW_RATINGS = 20
LOW_RATING = 3.5
POPULAR_USER_COUNT = 100_000

STORE_DOMAINS = (
    "google.com", "gstatic.com", "googleusercontent.com",
    "googleapis.com", "chrome.com",
)

ID_PATTERN = re.compile(r"(?<![a-p])[a-p]{32}(?![a-p])")

LIMITATIONS = [
    "Metadata analysis reads declarations and public listing text, not "
    "confirmed runtime behavior.",
    "Store listing text is written by the developer and may be inaccurate "
    "or out of date.",
    "File hashes are compared with verified_contents.json, but the "
    "signatures on that file are not cryptographically verified here.",
    "Package integrity checks need the complete package; a partial copy "
    "reports the missing files.",
    "Review indicators identify things worth investigating, not proof of "
    "malicious activity.",
]


class ListingUnavailable(Exception):
    pass


class PackageError(Exception):
    pass


def make_indicator(rule_id, indicator_type, severity, evidence, explanation):
    if not isinstance(evidence, list):
        evidence = [evidence]

    return {
        "rule_id": rule_id,
        "type": indicator_type,
        "severity": severity,
        "evidence": evidence,
        "explanation": explanation,
    }


def extract_extension_id(source):
    text = str(source)
    match = ID_PATTERN.search(text)

    if match:
        return match.group(0)

    match = ID_PATTERN.search(Path(text).stem)

    return match.group(0) if match else None


def build_store_url(source, extension_id):
    if str(source).startswith("http"):
        return str(source)

    return f"{STORE_DETAIL_URL}{extension_id}"


class Package:
    def __init__(self, path):
        self.path = Path(path)
        self._zip = None

        if self.path.is_dir():
            names = [
                p.relative_to(self.path).as_posix()
                for p in self.path.rglob("*") if p.is_file()
            ]
        else:
            try:
                self._zip = zipfile.ZipFile(self.path, "r")
            except (zipfile.BadZipFile, OSError) as error:
                raise PackageError(
                    f"{self.path} is not a readable ZIP or folder: {error}"
                )

            names = [
                n for n in self._zip.namelist() if not n.endswith("/")
            ]

        self.prefix = ""

        if "manifest.json" not in names:
            nested = [
                n for n in names
                if n.endswith("/manifest.json") and n.count("/") == 1
            ]

            if len(nested) == 1:
                self.prefix = nested[0][: -len("manifest.json")]

        self.names = [
            n[len(self.prefix):] for n in names if n.startswith(self.prefix)
        ]

    def has(self, name):
        return name in self.names

    def open(self, name):
        full = self.prefix + name

        if self._zip is not None:
            return self._zip.open(full)

        return (self.path / full).open("rb")

    def read(self, name):
        with self.open(name) as file:
            return file.read()

    def size_of(self, name):
        full = self.prefix + name

        if self._zip is not None:
            return self._zip.getinfo(full).file_size

        return (self.path / full).stat().st_size

    def close(self):
        if self._zip is not None:
            self._zip.close()


def b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def read_block(file, size):
    chunks = []
    remaining = size

    while remaining > 0:
        chunk = file.read(remaining)

        if not chunk:
            break

        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def treehash(file, block_size=4096):
    leaves = []

    while True:
        block = read_block(file, block_size)

        if not block and leaves:
            break

        leaves.append(hashlib.sha256(block).digest())

        if len(block) < block_size:
            break

    branch = max(block_size // 32, 2)
    nodes = leaves

    while len(nodes) > 1:
        nodes = [
            hashlib.sha256(b"".join(nodes[i:i + branch])).digest()
            for i in range(0, len(nodes), branch)
        ]

    return b64url_encode(nodes[0])


def read_verified_contents(package):
    name = "_metadata/verified_contents.json"

    if not package.has(name):
        return None

    try:
        items = json.loads(package.read(name).decode("utf-8-sig"))
        signed = items[0]["signed_content"]
        payload = json.loads(b64url_decode(signed["payload"]))

        files = {}
        block_size = 4096

        for group in payload.get("content_hashes", []):
            block_size = group.get("hash_block_size", block_size)

            for entry in group.get("files", []):
                files[entry["path"]] = entry["root_hash"]

        keys = [
            sig.get("header", {}).get("kid")
            for sig in signed.get("signatures", [])
        ]

    except (ValueError, KeyError, IndexError, TypeError) as error:
        return {"error": f"Could not decode verified_contents.json: {error}"}

    return {
        "item_id": payload.get("item_id"),
        "item_version": payload.get("item_version"),
        "protocol_version": payload.get("protocol_version"),
        "hash_block_size": block_size,
        "files": files,
        "signature_keys": [k for k in keys if k],
    }


def verify_files(package, verified):
    mismatched = []
    matching = 0

    listed = verified["files"]
    block_size = verified["hash_block_size"]

    present = [n for n in package.names if not n.startswith("_metadata/")]

    for name in present:
        if name not in listed:
            continue

        with package.open(name) as file:
            actual = treehash(file, block_size)

        if actual == listed[name]:
            matching += 1
        else:
            mismatched.append(name)

    return {
        "files_checked": matching + len(mismatched),
        "files_matching": matching,
        "files_modified": sorted(mismatched),
        "files_not_in_signed_list": sorted(
            n for n in present if n not in listed
        ),
        "signed_files_missing_from_package": sorted(
            n for n in listed if n not in package.names
        ),
    }


def read_package_manifest(package):
    if not package.has("manifest.json"):
        return None

    try:
        text = package.read("manifest.json").decode("utf-8-sig")
        manifest = json.loads(text)
    except (ValueError, OSError):
        return None

    return manifest if isinstance(manifest, dict) else None


def resolve_message(value, package, default_locale):
    if not isinstance(value, str):
        return value, False

    match = re.fullmatch(r"__MSG_(\w+)__", value)

    if not match:
        return value, True

    key = match.group(1).lower()

    for locale in dict.fromkeys([default_locale, "en"]):
        path = f"_locales/{locale}/messages.json"

        if not locale or not package.has(path):
            continue

        try:
            messages = json.loads(package.read(path).decode("utf-8-sig"))
        except (ValueError, OSError):
            continue

        lookup = {k.lower(): v for k, v in messages.items()}
        text = (lookup.get(key) or {}).get("message")

        if text:
            return text, True

    return value, False


def analyze_package(path):
    package = Package(path)

    try:
        errors = []
        warnings = []

        manifest = read_package_manifest(package)

        if manifest is None:
            errors.append("manifest.json was not found or could not be parsed.")
            manifest = {}

        locale = manifest.get("default_locale")

        name, name_ok = resolve_message(manifest.get("name"), package, locale)
        description, desc_ok = resolve_message(
            manifest.get("description"), package, locale)

        if not name_ok or not desc_ok:
            warnings.append(
                "Could not resolve a __MSG_ placeholder in the manifest; "
                "_locales may be missing."
            )

        verified = read_verified_contents(package)

        if isinstance(verified, dict) and "error" in verified:
            errors.append(verified["error"])
            verified = None

        integrity = verify_files(package, verified) if verified else None

        js_files = [n for n in package.names if n.endswith(".js")]

        return {
            "path": str(path),
            "file_count": len(package.names),
            "total_size_bytes": sum(package.size_of(n) for n in package.names),
            "js_file_count": len(js_files),
            "manifest": {
                "name": name,
                "version": manifest.get("version"),
                "description": description,
                "author": manifest.get("author"),
                "default_locale": locale,
                "update_url": manifest.get("update_url"),
                "declared_permissions": sorted({
                    p for p in (
                        list(manifest.get("permissions", []))
                        + list(manifest.get("optional_permissions", []))
                    ) if isinstance(p, str)
                }),
            },
            "signed_contents": (
                None if verified is None else {
                    "item_id": verified["item_id"],
                    "item_version": verified["item_version"],
                    "signature_keys": verified["signature_keys"],
                    "signed_by_webstore":
                        "webstore" in verified["signature_keys"],
                    "signed_by_publisher":
                        "publisher" in verified["signature_keys"],
                    "signed_file_count": len(verified["files"]),
                }
            ),
            "integrity": integrity,
            "errors": errors,
            "warnings": warnings,
        }

    finally:
        package.close()


def package_indicators(info, expected_id=None):
    review = []
    trust = []

    signed = info.get("signed_contents")
    integrity = info.get("integrity")
    manifest = info.get("manifest", {})

    if signed is None:
        review.append(make_indicator(
            "M101", "no_signed_contents", "informational",
            [{"file": "_metadata/verified_contents.json", "present": False}],
            "The package has no store-signed file list, so it may be an "
            "unpacked or developer copy. File integrity cannot be checked."))
    else:
        if not signed["signed_by_webstore"]:
            review.append(make_indicator(
                "M102", "not_signed_by_webstore", "review",
                [{"signature_keys": signed["signature_keys"]}],
                "The signed file list does not carry a Chrome Web Store "
                "signature. Check where this package came from."))
        else:
            trust.append(make_indicator(
                "T101", "signed_by_webstore", "informational",
                [{"signature_keys": signed["signature_keys"]}],
                "The file list is signed by the Chrome Web Store."))

        if (expected_id and signed["item_id"]
                and signed["item_id"] != expected_id):
            review.append(make_indicator(
                "M103", "extension_id_mismatch", "review",
                [{"signed_id": signed["item_id"], "expected_id": expected_id}],
                "The extension ID inside the package differs from the ID "
                "it was requested or named by."))

        if (manifest.get("version") and signed["item_version"]
                and manifest["version"] != signed["item_version"]):
            review.append(make_indicator(
                "M104", "version_mismatch", "review",
                [{"manifest_version": manifest["version"],
                  "signed_version": signed["item_version"]}],
                "The manifest version differs from the version the store "
                "signed. The manifest may have been changed."))

    if integrity:
        if integrity["files_modified"]:
            review.append(make_indicator(
                "M105", "modified_files", "review",
                integrity["files_modified"],
                "These files no longer match their signed hashes. They may "
                "have been changed after the store published them."))

        if integrity["files_not_in_signed_list"]:
            review.append(make_indicator(
                "M106", "unsigned_files", "review",
                integrity["files_not_in_signed_list"],
                "These files are in the package but not in the store's "
                "signed file list."))

        if integrity["signed_files_missing_from_package"]:
            review.append(make_indicator(
                "M107", "missing_signed_files", "informational",
                integrity["signed_files_missing_from_package"][:20],
                "Files in the signed list are absent, so this may be a "
                "partial copy of the package."))

        if (integrity["files_checked"] > 0
                and not integrity["files_modified"]
                and not integrity["files_not_in_signed_list"]
                and not integrity["signed_files_missing_from_package"]):
            trust.append(make_indicator(
                "T102", "files_match_signed_hashes", "informational",
                [{"files_checked": integrity["files_checked"]}],
                "Every file in the package matches its signed hash."))

    update_url = manifest.get("update_url")

    if update_url and update_url.rstrip("/") != STORE_UPDATE_URL:
        review.append(make_indicator(
            "M108", "non_store_update_url", "review",
            [{"update_url": update_url}],
            "The extension updates from somewhere other than the Chrome "
            "Web Store, so its code can change without store review."))

    return review, trust


def crx_to_zip(data):
    if data[:4] != b"Cr24":
        raise PackageError("Downloaded data is not a CRX package.")

    version = int.from_bytes(data[4:8], "little")

    if version == 3:
        start = 12 + int.from_bytes(data[8:12], "little")
    elif version == 2:
        start = (16 + int.from_bytes(data[8:12], "little")
                 + int.from_bytes(data[12:16], "little"))
    else:
        raise PackageError(f"Unsupported CRX version: {version}")

    return data[start:]


def download_package(extension_id, dest_dir=PACKAGE_DIR, refresh=False):
    dest = Path(dest_dir) / f"{extension_id}.zip"

    if dest.exists() and not refresh:
        return dest

    try:
        response = requests.get(
            CRX_DOWNLOAD_URL,
            params={
                "response": "redirect",
                "prodversion": CRX_PROD_VERSION,
                "acceptformat": "crx2,crx3",
                "x": f"id={extension_id}&uc",
            },
            headers=HEADERS,
            timeout=60,
            stream=True,
        )
        response.raise_for_status()

        chunks = []
        total = 0

        for chunk in response.iter_content(chunk_size=65536):
            total += len(chunk)

            if total > MAX_PACKAGE_BYTES:
                raise PackageError("Package is larger than the size limit.")

            chunks.append(chunk)

    except requests.RequestException as error:
        raise PackageError(f"Could not download {extension_id}: {error}")

    data = b"".join(chunks)

    if not data:
        raise PackageError(
            f"No package was returned for {extension_id}. It may be "
            "unlisted, removed, or require a newer Chrome version."
        )

    archive = crx_to_zip(data)

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(archive)

    return dest


def fetch_listing(url):
    try:
        response = requests.get(
            url,
            headers=HEADERS,
            params={"hl": "en"},
            timeout=20,
        )
        response.raise_for_status()
    except requests.RequestException as error:
        raise ListingUnavailable(f"Could not fetch {url}: {error}")

    return response.text


def render_listing(url):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise ListingUnavailable(
            "--browser needs Playwright: pip install playwright && "
            "playwright install chromium"
        )

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(extra_http_headers=HEADERS)
        page.goto(url + ("&" if "?" in url else "?") + "hl=en",
                  wait_until="networkidle", timeout=30000)
        html = page.content()
        browser.close()

    return html


def first_match(pattern, text, flags=0):
    match = re.search(pattern, text, flags)

    return match.group(1).strip() if match else None


def parse_count(value):
    if value is None:
        return None

    value = value.replace(",", "").strip()
    multiplier = 1

    if value.endswith("K"):
        multiplier, value = 1_000, value[:-1]
    elif value.endswith("M"):
        multiplier, value = 1_000_000, value[:-1]

    try:
        return int(float(value) * multiplier)
    except ValueError:
        return None


def section(text, start, end):
    match = re.search(
        rf"\n{re.escape(start)}\n(.*?)(?:\n{re.escape(end)}\n|\Z)",
        text,
        re.S,
    )

    return match.group(1) if match else ""


def is_store_link(href):
    host = urlparse(href).hostname or ""

    return any(host == d or host.endswith("." + d) for d in STORE_DOMAINS)


def find_link(soup, predicate):
    for anchor in soup.find_all("a", href=True):
        if predicate(anchor.get_text(" ", strip=True), anchor["href"]):
            return anchor["href"]

    return None


def parse_listing(html):
    soup = BeautifulSoup(html, "html.parser")

    def meta(prop):
        tag = (
            soup.find("meta", attrs={"property": prop})
            or soup.find("meta", attrs={"name": prop})
        )

        if tag and tag.get("content"):
            return tag["content"].strip()

        return None

    text = soup.get_text("\n")
    text = re.sub(r"[ \t\u00a0]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n", text)

    header = text.split("\nOverview\n")[0]
    details = section(text, "Details", "Privacy")
    privacy = section(text, "Privacy", "Support")

    title = meta("og:title") or (soup.title.string if soup.title else "")
    name = re.sub(r"\s*-\s*Chrome Web Store\s*$", "", title or "").strip()

    short_description = meta("og:description") or meta("description")

    overview = first_match(
        r"\nOverview\n(.*?)\n(?:\d(?:\.\d)?\s*out of|Details\n)",
        text,
        re.S,
    )

    if overview and short_description:
        overview = re.sub(
            rf"^{re.escape(short_description)}\s*", "", overview
        ).strip() or overview

    category = first_match(
        r"Extension\s*\n?\s*([A-Za-z&' ,/-]+?)\s*\n?\s*[\d,]+\s+users?\b",
        header,
    )

    rating_match = re.search(
        r"(\d(?:\.\d)?)\s*\(?\s*([\d.,]+[KM]?)\s*ratings?\b", header
    )

    rating = float(rating_match.group(1)) if rating_match else None
    rating_count = parse_count(rating_match.group(2)) if rating_match else None

    users = parse_count(first_match(r"([\d,]+)\s+users?\b", header))

    version = first_match(r"Version\s*\n?\s*([\w.\-]+)", details)

    updated_raw = first_match(
        r"Updated\s*\n?\s*([A-Z][a-z]+ \d{1,2}, \d{4})", details
    )

    last_updated = None

    if updated_raw:
        try:
            last_updated = datetime.strptime(
                updated_raw, "%B %d, %Y"
            ).date().isoformat()
        except ValueError:
            last_updated = updated_raw

    size = first_match(r"Size\s*\n?\s*([\d.]+\s*[KMG]i?B)", details)

    language_count = first_match(r"(\d+)\s+languages?", details)

    website = (
        find_link(soup, lambda t, h: t.lower() == "website" and not is_store_link(h))
        or find_link(
            soup,
            lambda t, h: h.startswith("http") and not is_store_link(h)
            and "privacy" not in t.lower() and "support" not in t.lower(),
        )
    )

    email = first_match(r"Email\s*\n?\s*([\w.+-]+@[\w-]+\.[\w.-]+)", details)

    if re.search(r"Non-trader", details):
        trader_status = "non-trader"
    elif re.search(r"\nTrader\n", details):
        trader_status = "trader"
    else:
        trader_status = None

    disclosure = first_match(r"(The developer has[^.]*\.)", privacy)

    collects_data = None

    if disclosure:
        low = disclosure.lower()

        if "not collect" in low:
            collects_data = False
        elif "collect" in low:
            collects_data = True

    policy_url = find_link(
        soup,
        lambda t, h: "privacy policy" in t.lower() and not is_store_link(h),
    )

    declarations = []
    collected_types = []

    if "This developer declares that your data is" in privacy:
        before, after = privacy.split(
            "This developer declares that your data is", 1
        )

        declarations = [
            line.strip(" -*•") for line in after.split("\n")
            if len(line.strip()) > 10
        ]

        if collects_data and disclosure and disclosure in before:
            for line in before.split(disclosure, 1)[1].split("\n"):
                line = line.strip(" -*•")

                if (
                    line
                    and not line.startswith("To learn more")
                    and "Chrome Enterprise" not in line
                    and "Manage extensions" not in line
                ):
                    collected_types.append(line)

    permission_text = first_match(
        r"Permission explanations?:\s*(.*?)(?:Data usage explanations?:|\Z)",
        overview or "",
        re.S,
    )

    data_usage_text = first_match(
        r"Data usage explanations?:\s*(.*)",
        overview or "",
        re.S,
    )

    badges = {
        "featured": bool(re.search(r"^Featured$", header, re.M)),
        "established_publisher": "no history of violations" in header,
        "verified_website": "Created by the owner of the listed website" in header,
        "recommended_practices": "Follows recommended practices" in header,
    }

    listing = {
        "name": name or None,
        "category": category,
        "short_description": short_description,
        "long_description": overview,
        "users": users,
        "rating": rating,
        "rating_count": rating_count,
        "version": version,
        "last_updated": last_updated,
        "size": size,
        "language_count": int(language_count) if language_count else None,
        "developer_website": website,
        "developer_email": email,
        "trader_status": trader_status,
        "privacy_policy_url": policy_url,
        "data_disclosure": disclosure,
        "collects_data": collects_data,
        "collected_data_types": collected_types,
        "data_declarations": declarations,
        "permission_explanations": permission_text,
        "data_usage_explanations": data_usage_text,
        "badges": badges,
    }

    if not name or (users is None and version is None):
        raise ListingUnavailable(
            "The page did not contain the expected listing content. "
            "It may be rendered by JavaScript or blocked. Try --browser, "
            "or save the page in Chrome and use --html."
        )

    return listing


def load_manual_listing(extension_id, manual_dir=MANUAL_DIR):
    path = Path(manual_dir) / f"{extension_id}.json"

    if not path.exists():
        return None

    with path.open("r", encoding="utf-8") as file:
        listing = json.load(file)

    listing.setdefault("badges", {})

    return listing


def days_since(iso_date):
    try:
        return (date.today() - date.fromisoformat(iso_date)).days
    except (TypeError, ValueError):
        return None


def listing_indicators(listing):
    review = []
    trust = []
    badges = listing.get("badges") or {}

    age = days_since(listing.get("last_updated"))

    if age is not None and age > STALE_DAYS:
        review.append(make_indicator(
            "M001", "stale_listing", "review",
            [{"last_updated": listing["last_updated"], "days": age}],
            f"The extension has not been updated in about {age // 30} "
            "months, so security problems may go unfixed."))

    users = listing.get("users")

    if users is not None and users < LOW_USER_COUNT:
        review.append(make_indicator(
            "M002", "low_user_count", "review", [{"users": users}],
            "Few people use this extension, so there is little "
            "community history to rely on."))

    count = listing.get("rating_count")
    rating = listing.get("rating")

    if count is not None and count < FEW_RATINGS:
        review.append(make_indicator(
            "M003", "few_ratings", "review", [{"rating_count": count}],
            "The extension has very few ratings, so its average rating "
            "is not reliable."))

    if rating is not None and rating < LOW_RATING:
        review.append(make_indicator(
            "M004", "low_rating", "review", [{"rating": rating}],
            "Users rate this extension poorly."))

    if not listing.get("privacy_policy_url"):
        review.append(make_indicator(
            "M005", "no_privacy_policy", "review",
            [{"privacy_policy_url": None}],
            "The listing has no privacy policy link."))

    if not listing.get("developer_website"):
        review.append(make_indicator(
            "M006", "no_developer_website", "review",
            [{"developer_website": None}],
            "The developer lists no website."))

    if not listing.get("data_disclosure"):
        review.append(make_indicator(
            "M007", "no_data_disclosure", "review",
            [{"data_disclosure": None}],
            "The listing has no data-collection disclosure."))

    if listing.get("collects_data"):
        review.append(make_indicator(
            "M008", "collects_user_data", "informational",
            [{"collected_data_types":
                listing.get("collected_data_types") or []}],
            "The developer says it collects or uses user data."))

    if badges.get("featured"):
        trust.append(make_indicator(
            "T001", "featured", "informational", [{"featured": True}],
            "Featured by the Chrome Web Store."))

    if badges.get("established_publisher"):
        trust.append(make_indicator(
            "T002", "good_publisher_record", "informational",
            [{"established_publisher": True}],
            "The publisher has no history of violations."))

    if badges.get("verified_website"):
        trust.append(make_indicator(
            "T003", "verified_website", "informational",
            [{"verified_website": True}],
            "Created by the owner of the listed website."))

    if badges.get("recommended_practices"):
        trust.append(make_indicator(
            "T004", "recommended_practices", "informational",
            [{"recommended_practices": True}],
            "Follows recommended practices for Chrome extensions."))

    if users is not None and users >= POPULAR_USER_COUNT:
        trust.append(make_indicator(
            "T005", "widely_used", "informational", [{"users": users}],
            "Many people use this extension."))

    return review, trust


def cross_check(listing, package_info):
    manifest = package_info["manifest"]
    declared = manifest["declared_permissions"]

    listing_text = " ".join(
        part for part in (
            listing.get("long_description"),
            listing.get("permission_explanations"),
            listing.get("data_usage_explanations"),
        ) if part
    ).lower()

    package_version = manifest.get("version")
    listing_version = listing.get("version")

    return {
        "package_version": package_version,
        "listing_version": listing_version,
        "version_matches": (
            package_version == listing_version
            if package_version and listing_version else None
        ),
        "developer_explained_permissions": bool(
            listing.get("permission_explanations")
        ),
        "declared_permissions": declared,
        "permissions_not_mentioned_in_listing": [
            p for p in declared if p.lower() not in listing_text
        ],
        "note": (
            "A permission name missing from the listing text only means the "
            "developer did not use that word; many listings never mention "
            "permissions at all."
        ),
    }


def get_listing(source, extension_id, html_path=None, use_browser=False,
                manual_dir=MANUAL_DIR, raw_dir=None):
    url = build_store_url(source, extension_id)

    if html_path:
        html = Path(html_path).read_text(encoding="utf-8", errors="ignore")
        return parse_listing(html), "html_file", url

    try:
        html = render_listing(url) if use_browser else fetch_listing(url)

        if raw_dir:
            raw_dir = Path(raw_dir)
            raw_dir.mkdir(parents=True, exist_ok=True)
            (raw_dir / f"{extension_id}.html").write_text(
                html, encoding="utf-8")

        return (
            parse_listing(html),
            "browser" if use_browser else "http",
            url,
        )

    except ListingUnavailable as error:
        manual = load_manual_listing(extension_id, manual_dir)

        if manual is None:
            raise error

        return manual, "manual", url


def build_metadata_report(source, package_path=None, html_path=None,
                          use_browser=False, offline=False, download=True,
                          refresh=False, manual_dir=MANUAL_DIR, raw_dir=None,
                          package_dir=PACKAGE_DIR):
    source_text = str(source)
    looks_like_path = (
        not source_text.startswith("http")
        and not ID_PATTERN.fullmatch(source_text)
    )

    if package_path is None and Path(source_text).exists():
        package_path = source
    elif package_path is None and looks_like_path:
        raise PackageError(f"No such file or folder: {source_text}")

    package_info = None
    package_origin = "provided" if package_path is not None else None
    errors = []
    warnings = []

    if package_path is None and download and not offline:
        source_id = extract_extension_id(source_text)

        if source_id:
            try:
                package_path = download_package(
                    source_id, package_dir, refresh)
                package_origin = "downloaded"
            except PackageError as error:
                warnings.append(f"Package download failed: {error}")

    if package_path is not None:
        try:
            package_info = analyze_package(package_path)
        except PackageError as error:
            if offline or str(source) == str(package_path):
                raise
            errors.append(str(error))

    if package_info:
        errors += package_info["errors"]
        warnings += package_info["warnings"]

    signed = (package_info or {}).get("signed_contents") or {}

    extension_id = (
        signed.get("item_id")
        or extract_extension_id(package_path or "")
        or extract_extension_id(source)
    )

    expected_id = (
        extract_extension_id(package_path or "")
        or (extract_extension_id(source)
            if not Path(str(source)).exists() else None)
    )

    if not extension_id:
        raise ValueError(
            "Could not find a 32-letter extension ID in "
            f"{source!r}. Pass the store URL or the ID."
        )

    listing = None
    method = "package_only"
    store_url = build_store_url(
        source if str(source).startswith("http") else extension_id,
        extension_id,
    )

    if not offline:
        try:
            listing, method, store_url = get_listing(
                source if str(source).startswith("http") else extension_id,
                extension_id, html_path, use_browser, manual_dir, raw_dir,
            )
        except ListingUnavailable as error:
            if package_info is None:
                raise

            warnings.append(f"Store listing unavailable: {error}")

    review = []
    trust = []

    if package_info:
        r, t = package_indicators(package_info, expected_id)
        review += r
        trust += t

    if listing:
        r, t = listing_indicators(listing)
        review += r
        trust += t

    crosscheck = (
        cross_check(listing, package_info) if listing and package_info else None
    )

    if crosscheck and crosscheck["version_matches"] is False:
        review.append(make_indicator(
            "M009", "version_differs_from_store", "informational",
            [{"package_version": crosscheck["package_version"],
              "store_version": crosscheck["listing_version"]}],
            "The package version differs from the current store version. "
            "The package may be older or newer than what users install."))

    L = listing or {}
    manifest_info = (package_info or {}).get("manifest", {})

    package_summary = None

    if package_info:
        package_summary = {
            "path": package_info["path"],
            "file_count": package_info["file_count"],
            "js_file_count": package_info["js_file_count"],
            "total_size_bytes": package_info["total_size_bytes"],
            "update_url": manifest_info.get("update_url"),
            "signed_contents": package_info["signed_contents"],
            "integrity": package_info["integrity"],
        }

    return {
        "extension": {
            "id": extension_id,
            "name": L.get("name") or manifest_info.get("name"),
            "store_url": store_url,
        },
        "stated_purpose": {
            "category": L.get("category"),
            "short_description": L.get("short_description"),
            "long_description": L.get("long_description"),
            "package_description": manifest_info.get("description"),
        },
        "popularity": {
            "users": L.get("users"),
            "rating": L.get("rating"),
            "rating_count": L.get("rating_count"),
        },
        "maintenance": {
            "version": L.get("version") or manifest_info.get("version"),
            "last_updated": L.get("last_updated"),
            "days_since_update": days_since(L.get("last_updated")),
            "size": L.get("size"),
        },
        "developer": {
            "name": manifest_info.get("author"),
            "website": L.get("developer_website"),
            "email": L.get("developer_email"),
            "trader_status": L.get("trader_status"),
        },
        "privacy": {
            "policy_url": L.get("privacy_policy_url"),
            "disclosure": L.get("data_disclosure"),
            "collects_data": L.get("collects_data"),
            "collected_data_types": L.get("collected_data_types", []),
            "declarations": L.get("data_declarations", []),
        },
        "developer_explanations": {
            "permissions": L.get("permission_explanations"),
            "data_usage": L.get("data_usage_explanations"),
        },
        "badges": L.get("badges", {}),
        "package": package_summary,
        "manifest_crosscheck": crosscheck,
        "analysis": {
            "basic_structure_valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "review_indicators": review,
            "trust_indicators": trust,
            "limitations": LIMITATIONS,
        },
        "source": {
            "store_listing": method,
            "package": package_origin if package_info else None,
            "retrieved_at": datetime.now().isoformat(timespec="seconds"),
        },
    }


def read_batch_file(path):
    lines = Path(path).read_text(encoding="utf-8").splitlines()

    return [
        line.strip() for line in lines
        if line.strip() and not line.strip().startswith("#")
    ]


def run_batch(sources, use_browser=False, offline=False, download=True,
              refresh=False):
    OUTPUT_DIR.mkdir(exist_ok=True)

    reports = []

    for source in sources:
        try:
            report = build_metadata_report(
                source,
                use_browser=use_browser,
                offline=offline,
                download=download,
                refresh=refresh,
                raw_dir=OUTPUT_DIR / "raw",
            )
        except (ListingUnavailable, PackageError, ValueError) as error:
            print(f"FAILED  {source}\n        {error}")
            continue

        reports.append(report)

        ext = report["extension"]

        (OUTPUT_DIR / f"{ext['id']}_metadata.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8")

        print(
            f"ok      {ext['name']}  "
            f"({report['popularity']['users']} users, "
            f"{len(report['analysis']['review_indicators'])} review "
            f"indicators, listing: {report['source']['store_listing']})"
        )

        if not offline:
            time.sleep(2)

    (OUTPUT_DIR / "all_metadata.json").write_text(
        json.dumps(reports, indent=2), encoding="utf-8")

    print(f"\nSaved {len(reports)} reports to {OUTPUT_DIR}/")


def main():
    parser = argparse.ArgumentParser(
        description="Metadata analyzer for Chrome extensions."
    )

    parser.add_argument(
        "source", nargs="?",
        help="extension package (.zip or folder), store URL, or extension ID")

    parser.add_argument(
        "--package", "--dir", dest="package_path",
        help="package to analyze alongside a store URL or ID")

    parser.add_argument(
        "--offline", action="store_true",
        help="skip the store listing; report on the package only")

    parser.add_argument(
        "--no-download", action="store_true",
        help="do not download the package for a store URL or ID")

    parser.add_argument(
        "--refresh", action="store_true",
        help="download the package again even if a copy is saved")

    parser.add_argument(
        "--batch", metavar="FILE",
        help="text file with one package path, store URL, or ID per line")

    parser.add_argument(
        "--html", metavar="FILE",
        help="parse a store page saved from the browser")

    parser.add_argument(
        "--browser", action="store_true",
        help="render the page with Playwright instead of a plain request")

    args = parser.parse_args()

    if args.batch:
        run_batch(read_batch_file(args.batch), use_browser=args.browser,
                  offline=args.offline, download=not args.no_download,
                  refresh=args.refresh)
        return

    if not args.source:
        parser.print_usage()
        sys.exit(1)

    try:
        report = build_metadata_report(
            args.source,
            package_path=args.package_path,
            html_path=args.html,
            use_browser=args.browser,
            offline=args.offline,
            download=not args.no_download,
            refresh=args.refresh,
        )

        print(json.dumps(report, indent=2, ensure_ascii=False))

    except (ListingUnavailable, PackageError, ValueError) as error:
        print(json.dumps({"error": str(error)}, indent=2))
        sys.exit(1)


if __name__ == "__main__":
    main()