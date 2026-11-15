"""
metadata_analyzer.py

Metadata analyzer for the Browser Extension Permission Explainer.

The manifest analyzer reports what an extension is ALLOWED to do, and the
access/network analyzers report what its code APPEARS to do. This module
answers a different question: what does the extension SAY it is for, and
can we trust where it came from? It reads two sources:

  1. The extension package (the same .zip the manifest analyzer reads, or an
     unpacked folder): the extension ID and version signed by the store in
     _metadata/verified_contents.json, whether every file still matches its
     signed hash, the update source, and the real name/description behind
     manifest placeholders such as __MSG_extension_description__.

  2. The public Chrome Web Store listing: purpose, category, popularity,
     update history, developer, privacy disclosures, and the permission
     explanations developers write themselves. (No login, no installation.)

This module only gathers facts. The rules that turn those facts into review
indicators live in metadata_rules.py (run_metadata_rules), the same split as
manifestanalyzer.py / manifestruleengine.py and access_report.py / access_rules.py:

    python analyzer/metadata_analyzer.py <source>     # facts only
    python analyzer/metadata_rules.py <source>        # facts + review indicators

Usage:
    pip install requests beautifulsoup4

    python metadata_analyzer.py <store_url | extension_id>      # ANY extension: downloads the package + reads the listing
    python metadata_analyzer.py <package.zip | folder>          # a package you already have + its store listing
    python metadata_analyzer.py <package.zip> --offline         # package only, no network
    python metadata_analyzer.py <store_url> --no-download       # listing only
    python metadata_analyzer.py <store_url> --package <zip>     # listing + a package you supply
    python metadata_analyzer.py --batch sample_extensions.txt   # many; saved to metadata_output/
    python metadata_analyzer.py <source> --html saved_page.html # parse a page saved by hand
    python metadata_analyzer.py <source> --browser              # render with Playwright (optional)

Given only a store URL or ID, the package is downloaded from Google's
extension update service and saved to metadata_output/packages/<id>.zip.
That same zip can be handed to the manifest and code analyzers:

    from metadata_analyzer import download_package
    zip_path = download_package("eimadpbcbfnmbkopoojfekhnkhdbieeh")

Use from other code:
    from metadata_analyzer import build_metadata_report
    from metadata_rules import run_metadata_rules
    report = build_metadata_report("https://chromewebstore.google.com/detail/.../<id>")
    report = run_metadata_rules(build_metadata_report("eimadpbcbfnmbkopoojfekhnkhdbieeh.zip"))

Works for Chrome Web Store extensions (Chrome IDs, store URLs, CRX/zip
packages). Edge Add-ons and Firefox add-ons use different stores and formats.

If scraping fails (page layout changed, blocked, offline), put a hand-built
listing at metadata_manual/<extension_id>.json using the same flat keys as
parse_listing() returns (name, users, rating, ...). It is used automatically
as a fallback, and the report records that the source was "manual".

This is a heuristic analysis. An indicator is a reason to look closer, not
proof of a problem.
"""

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


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

STORE_DETAIL_URL = "https://chromewebstore.google.com/detail/"

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

# Google's extension update service, used to download a package by ID.
CRX_DOWNLOAD_URL = "https://clients2.google.com/service/update2/crx"
CRX_PROD_VERSION = "140.0.0.0"
MAX_PACKAGE_BYTES = 100 * 1024 * 1024

# Domains that are part of the store page itself, not the developer.
STORE_DOMAINS = (
    "google.com", "gstatic.com", "googleusercontent.com",
    "googleapis.com", "chrome.com",
)

ID_PATTERN = re.compile(r"(?<![a-p])[a-p]{32}(?![a-p])")


class ListingUnavailable(Exception):
    """The store page could not be fetched or did not contain a listing."""


class PackageError(Exception):
    """The extension package could not be read."""


# ---------------------------------------------------------------------------
# Identifying the extension
# ---------------------------------------------------------------------------

def extract_extension_id(source):
    """
    Find the 32-letter extension ID in a store URL, a bare ID,
    or the name of an extension folder / zip (e.g. "abcd...xyz.zip").
    """

    text = str(source)
    match = ID_PATTERN.search(text)

    if match:
        return match.group(0)

    match = ID_PATTERN.search(Path(text).stem)

    return match.group(0) if match else None


def build_store_url(source, extension_id):
    """
    Use the URL if one was given. Otherwise fall back to the ID-only
    store address, which the store normally redirects to the full page.
    """

    if str(source).startswith("http"):
        return str(source)

    return f"{STORE_DETAIL_URL}{extension_id}"


# ---------------------------------------------------------------------------
# Package reading (zip or unpacked folder)
# ---------------------------------------------------------------------------

class Package:
    """
    Read-only view of an extension package: a .zip or an unpacked folder.
    Handles a single enclosing folder inside the zip.
    """

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

        # If manifest.json is not at the root, accept one enclosing folder.
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
        """Binary file object for one file in the package."""

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
    """Read exactly `size` bytes unless the file ends first."""

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
    """
    Chrome's per-file content hash: SHA-256 of each 4096-byte block, then a
    tree of SHA-256 over groups of (block_size / 32) hashes until one root
    remains. Returned base64url without padding, as in verified_contents.json.
    """

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
    """
    Decode _metadata/verified_contents.json.

    Returns None if the file is absent, or a dict with the signed item ID,
    version, per-file hashes, and the names of the signing keys.
    Malformed content returns {"error": "..."}.
    """

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
    """
    Compare every file in the package with its signed hash.
    """

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
    """
    Parse manifest.json from the package, or None.
    """

    if not package.has("manifest.json"):
        return None

    try:
        text = package.read("manifest.json").decode("utf-8-sig")
        manifest = json.loads(text)

    except (ValueError, OSError):
        return None

    return manifest if isinstance(manifest, dict) else None


def resolve_message(value, package, default_locale):
    """
    Replace a manifest placeholder like __MSG_extension_description__ with
    the text from _locales/<locale>/messages.json. Returns (text, resolved).
    """

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
    """
    Read the metadata that travels inside the extension package.
    """

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


# ---------------------------------------------------------------------------
# Downloading a package by extension ID
# ---------------------------------------------------------------------------

def crx_to_zip(data):
    """
    Strip the CRX header (CRX2 or CRX3) and return the ZIP bytes inside.
    """

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
    """
    Download an extension's package from the Chrome update service and save
    it as <dest_dir>/<extension_id>.zip. An existing copy is reused unless
    refresh is True. Returns the path. Raises PackageError on failure.
    """

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


# ---------------------------------------------------------------------------
# Fetching the store listing
# ---------------------------------------------------------------------------

def fetch_listing(url):
    """
    Download the store page. Raises ListingUnavailable on any failure.
    """

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
    """
    Optional fallback: load the page in a real browser (needs
    `pip install playwright` and `playwright install chromium`).
    """

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


# ---------------------------------------------------------------------------
# Parsing the listing
# ---------------------------------------------------------------------------

def first_match(pattern, text, flags=0):
    """
    Return the first capture group of a regex, stripped, or None.
    """

    match = re.search(pattern, text, flags)

    return match.group(1).strip() if match else None


def parse_count(value):
    """
    Convert '3.5K' -> 3500, '2,000,000' -> 2000000.
    """

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
    """
    Text between a line that is exactly `start` and the next line
    that is exactly `end` (or the end of the text).
    """

    match = re.search(
        rf"\n{re.escape(start)}\n(.*?)(?:\n{re.escape(end)}\n|\Z)",
        text,
        re.S,
    )

    return match.group(1) if match else ""


def is_store_link(href):
    """
    True for links that belong to the store page itself.
    """

    host = urlparse(href).hostname or ""

    return any(host == d or host.endswith("." + d) for d in STORE_DOMAINS)


def find_link(soup, predicate):
    """
    First anchor whose (text, href) satisfies the predicate.
    """

    for anchor in soup.find_all("a", href=True):

        if predicate(anchor.get_text(" ", strip=True), anchor["href"]):
            return anchor["href"]

    return None


def parse_listing(html):
    """
    Turn a store page into one flat dictionary of listing fields.
    Missing fields are None. Raises ListingUnavailable if the page does
    not look like a listing at all.
    """

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

    # Regions of the page, so patterns do not match the wrong place.
    header = text.split("\nOverview\n")[0]
    details = section(text, "Details", "Privacy")
    privacy = section(text, "Privacy", "Support")

    # ---- name and purpose ------------------------------------------------

    title = meta("og:title") or (soup.title.string if soup.title else "")
    name = re.sub(r"\s*-\s*Chrome Web Store\s*$", "", title or "").strip()

    short_description = meta("og:description") or meta("description")

    overview = first_match(
        r"\nOverview\n(.*?)\n(?:\d(?:\.\d)?\s*out of|Details\n)",
        text,
        re.S,
    )

    if overview and short_description:
        # The overview repeats the short description as its first line.
        overview = re.sub(
            rf"^{re.escape(short_description)}\s*", "", overview
        ).strip() or overview

    category = first_match(
        r"Extension\s*\n?\s*([A-Za-z&' ,/-]+?)\s*\n?\s*[\d,]+\s+users?\b",
        header,
    )

    # ---- popularity ------------------------------------------------------

    rating_match = re.search(
        r"(\d(?:\.\d)?)\s*\(?\s*([\d.,]+[KM]?)\s*ratings?\b", header
    )

    rating = float(rating_match.group(1)) if rating_match else None
    rating_count = parse_count(rating_match.group(2)) if rating_match else None

    users = parse_count(first_match(r"([\d,]+)\s+users?\b", header))

    # ---- maintenance -----------------------------------------------------

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

    # ---- developer -------------------------------------------------------

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

    # ---- privacy ---------------------------------------------------------

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

        # Best effort: lines listing what is collected sit between the
        # disclosure sentence and the declarations. (Not seen on every page.)
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

    # ---- developer-written permission explanations -----------------------

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

    # ---- badges ----------------------------------------------------------

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

    # A real listing always has a name plus users or a version.
    if not name or (users is None and version is None):
        raise ListingUnavailable(
            "The page did not contain the expected listing content. "
            "It may be rendered by JavaScript or blocked. Try --browser, "
            "or save the page in Chrome and use --html."
        )

    return listing


def load_manual_listing(extension_id, manual_dir=MANUAL_DIR):
    """
    Hand-built listing (same flat keys as parse_listing), or None.
    """

    path = Path(manual_dir) / f"{extension_id}.json"

    if not path.exists():
        return None

    with path.open("r", encoding="utf-8") as file:
        listing = json.load(file)

    listing.setdefault("badges", {})

    return listing


# ---------------------------------------------------------------------------
# Listing helpers
# ---------------------------------------------------------------------------

def days_since(iso_date):
    """
    Whole days since an ISO date, or None if it is not a date.
    """

    try:
        return (date.today() - date.fromisoformat(iso_date)).days

    except (TypeError, ValueError):
        return None


def cross_check(listing, package_info):
    """
    Compare the store listing with the package.

    - version: the package may simply be older or newer than the store.
    - permissions: which declared API permissions are never mentioned in the
      developer's own listing text.
    """

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


# ---------------------------------------------------------------------------
# Building the report
# ---------------------------------------------------------------------------

def get_listing(source, extension_id, html_path=None, use_browser=False,
                manual_dir=MANUAL_DIR, raw_dir=None):
    """
    Return (listing, method, store_url) using the first source that works:
    a saved HTML file, an HTTP fetch, a browser render, then a manual file.
    """

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
    """
    Build the structured metadata report for one extension.

    source: a package (.zip or folder), a store URL, or an extension ID.
    package_path: optional package to analyze alongside a URL/ID source.
    offline: no network at all; report on the package only.
    download: for a URL/ID with no package, download the package by ID.
    refresh: download again even if a copy is already saved.
    """

    source_text = str(source)
    looks_like_path = (
        not source_text.startswith("http")
        and not ID_PATTERN.fullmatch(source_text)
    )

    # A source that exists on disk is a package; anything else is a URL or ID.
    if package_path is None and Path(source_text).exists():
        package_path = source

    elif package_path is None and looks_like_path:
        raise PackageError(f"No such file or folder: {source_text}")

    package_info = None
    package_origin = "provided" if package_path is not None else None
    errors = []
    warnings = []

    # Any extension: fetch its package by ID when none was supplied.
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

    # Work out the extension ID: signed ID first, then names the user gave.
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

    # Store listing (optional when a package is available).
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

    crosscheck = (
        cross_check(listing, package_info) if listing and package_info else None
    )

    L = listing or {}
    manifest_info = (package_info or {}).get("manifest", {})

    package_summary = None

    if package_info:
        package_summary = {
            "path": package_info["path"],
            "file_count": package_info["file_count"],
            "js_file_count": package_info["js_file_count"],
            "total_size_bytes": package_info["total_size_bytes"],
            "version": manifest_info.get("version"),
            "update_url": manifest_info.get("update_url"),
            "expected_id": expected_id,
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
        },

        "source": {
            "store_listing": method,
            "listing_available": listing is not None,
            "package": package_origin if package_info else None,
            "retrieved_at": datetime.now().isoformat(timespec="seconds"),
        },
    }


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def load_rules():
    """
    Import the rule engine only when needed (it works with either the flat
    layout used by analyzer/ scripts or the analyzer package).
    """

    try:
        from metadata_rules import run_metadata_rules

    except ImportError:
        from analyzer.metadata_rules import run_metadata_rules

    return run_metadata_rules


def read_batch_file(path):
    """
    One package path, store URL, or ID per line. Blank lines and # comments
    are skipped.
    """

    lines = Path(path).read_text(encoding="utf-8").splitlines()

    return [
        line.strip() for line in lines
        if line.strip() and not line.strip().startswith("#")
    ]


def run_batch(sources, use_browser=False, offline=False, download=True,
              refresh=False):
    """
    Analyze many extensions and apply the metadata rules, saving one JSON
    file each plus one combined file.
    """

    run_metadata_rules = load_rules()

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

        report = run_metadata_rules(report)
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
            time.sleep(2)  # be polite to the store

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
