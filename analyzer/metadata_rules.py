import copy
import sys
from datetime import date
import json


STALE_DAYS = 548
LOW_USER_COUNT = 1000
FEW_RATINGS = 20
LOW_RATING = 3.5
POPULAR_USER_COUNT = 100_000

STORE_UPDATE_URL = "https://clients2.google.com/service/update2/crx"

WEAK_TRUST_TYPES = {
    "stale_listing",
    "low_user_count",
    "few_ratings",
    "low_rating",
    "no_privacy_policy",
    "no_developer_website",
    "no_data_disclosure",
}

BROAD_ACCESS_TYPES = {
    "broad_host_access",
    "broad_content_script_injection",
}

LIMITATIONS = [
    "Metadata rules flag declarations and public listing text for review; "
    "they do not prove malicious behavior.",
    "Store listing text is written by the developer and may be inaccurate "
    "or out of date.",
    "File hashes are compared with verified_contents.json, but the "
    "signatures on that file are not cryptographically verified.",
    "Package integrity rules need the complete package; a partial copy "
    "reports the missing files.",
    "Thresholds such as user counts and update age are heuristics.",
]


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


def _section(report, key):
    value = report.get(key)
    return value if isinstance(value, dict) else {}


def _days_since(iso_date):
    try:
        return (date.today() - date.fromisoformat(iso_date)).days
    except (TypeError, ValueError):
        return None


def _listing_rules(report):
    review = []
    trust = []

    popularity = _section(report, "popularity")
    maintenance = _section(report, "maintenance")
    developer = _section(report, "developer")
    privacy = _section(report, "privacy")
    badges = _section(report, "badges")

    days = maintenance.get("days_since_update")
    if days is None:
        days = _days_since(maintenance.get("last_updated"))

    if isinstance(days, int) and days > STALE_DAYS:
        review.append(make_indicator(
            "M001", "stale_listing", "review",
            [{"last_updated": maintenance.get("last_updated"), "days": days}],
            f"The extension has not been updated in about {days // 30} "
            "months, so security problems may go unfixed.",
        ))

    users = popularity.get("users")
    if isinstance(users, int) and users < LOW_USER_COUNT:
        review.append(make_indicator(
            "M002", "low_user_count", "review", [{"users": users}],
            "Few people use this extension, so there is little community "
            "history to rely on.",
        ))

    count = popularity.get("rating_count")
    if isinstance(count, int) and count < FEW_RATINGS:
        review.append(make_indicator(
            "M003", "few_ratings", "review", [{"rating_count": count}],
            "The extension has very few ratings, so its average rating "
            "is not reliable.",
        ))

    rating = popularity.get("rating")
    if isinstance(rating, (int, float)) and rating < LOW_RATING:
        review.append(make_indicator(
            "M004", "low_rating", "review", [{"rating": rating}],
            "Users rate this extension poorly.",
        ))

    if not privacy.get("policy_url"):
        review.append(make_indicator(
            "M005", "no_privacy_policy", "review",
            [{"privacy_policy_url": None}],
            "The listing has no privacy policy link.",
        ))

    if not developer.get("website"):
        review.append(make_indicator(
            "M006", "no_developer_website", "review",
            [{"developer_website": None}],
            "The developer lists no website.",
        ))

    if not privacy.get("disclosure"):
        review.append(make_indicator(
            "M007", "no_data_disclosure", "review",
            [{"data_disclosure": None}],
            "The listing has no data-collection disclosure.",
        ))

    if privacy.get("collects_data") is True:
        types = privacy.get("collected_data_types")
        review.append(make_indicator(
            "M008", "collects_user_data", "informational",
            [{"collected_data_types": types if isinstance(types, list) else []}],
            "The developer says it collects or uses user data.",
        ))

    crosscheck = _section(report, "manifest_crosscheck")
    if crosscheck.get("version_matches") is False:
        review.append(make_indicator(
            "M009", "version_differs_from_store", "informational",
            [{"package_version": crosscheck.get("package_version"),
              "store_version": crosscheck.get("listing_version")}],
            "The package version differs from the current store version. "
            "The package may be older or newer than what users install.",
        ))

    if badges.get("featured"):
        trust.append(make_indicator(
            "T001", "featured", "informational", [{"featured": True}],
            "Featured by the Chrome Web Store.",
        ))

    if badges.get("established_publisher"):
        trust.append(make_indicator(
            "T002", "good_publisher_record", "informational",
            [{"established_publisher": True}],
            "The publisher has no history of violations.",
        ))

    if badges.get("verified_website"):
        trust.append(make_indicator(
            "T003", "verified_website", "informational",
            [{"verified_website": True}],
            "Created by the owner of the listed website.",
        ))

    if badges.get("recommended_practices"):
        trust.append(make_indicator(
            "T004", "recommended_practices", "informational",
            [{"recommended_practices": True}],
            "Follows recommended practices for Chrome extensions.",
        ))

    if isinstance(users, int) and users >= POPULAR_USER_COUNT:
        trust.append(make_indicator(
            "T005", "widely_used", "informational", [{"users": users}],
            "Many people use this extension.",
        ))

    return review, trust


def _package_rules(report):
    review = []
    trust = []

    package = _section(report, "package")
    signed = package.get("signed_contents")
    signed = signed if isinstance(signed, dict) else None
    integrity = package.get("integrity")
    integrity = integrity if isinstance(integrity, dict) else None

    if signed is None:
        review.append(make_indicator(
            "M101", "no_signed_contents", "informational",
            [{"file": "_metadata/verified_contents.json", "present": False}],
            "The package has no store-signed file list, so it may be an "
            "unpacked or developer copy. File integrity cannot be checked.",
        ))
    else:
        keys = signed.get("signature_keys") or []

        if not signed.get("signed_by_webstore"):
            review.append(make_indicator(
                "M102", "not_signed_by_webstore", "review",
                [{"signature_keys": keys}],
                "The signed file list does not carry a Chrome Web Store "
                "signature. Check where this package came from.",
            ))
        else:
            trust.append(make_indicator(
                "T101", "signed_by_webstore", "informational",
                [{"signature_keys": keys}],
                "The file list is signed by the Chrome Web Store.",
            ))

        expected_id = package.get("expected_id")
        if expected_id and signed.get("item_id") and signed["item_id"] != expected_id:
            review.append(make_indicator(
                "M103", "extension_id_mismatch", "review",
                [{"signed_id": signed["item_id"], "expected_id": expected_id}],
                "The extension ID inside the package differs from the ID "
                "it was requested or named by.",
            ))

        version = package.get("version")
        if version and signed.get("item_version") and version != signed["item_version"]:
            review.append(make_indicator(
                "M104", "version_mismatch", "review",
                [{"manifest_version": version,
                  "signed_version": signed["item_version"]}],
                "The manifest version differs from the version the store "
                "signed. The manifest may have been changed.",
            ))

    if integrity:
        modified = integrity.get("files_modified") or []
        unsigned = integrity.get("files_not_in_signed_list") or []
        missing = integrity.get("signed_files_missing_from_package") or []

        if modified:
            review.append(make_indicator(
                "M105", "modified_files", "review", list(modified),
                "These files no longer match their signed hashes. They may "
                "have been changed after the store published them.",
            ))

        if unsigned:
            review.append(make_indicator(
                "M106", "unsigned_files", "review", list(unsigned),
                "These files are in the package but not in the store's "
                "signed file list.",
            ))

        if missing:
            review.append(make_indicator(
                "M107", "missing_signed_files", "informational", list(missing[:20]),
                "Files in the signed list are absent, so this may be a "
                "partial copy of the package.",
            ))

        if integrity.get("files_checked", 0) > 0 and not (modified or unsigned or missing):
            trust.append(make_indicator(
                "T102", "files_match_signed_hashes", "informational",
                [{"files_checked": integrity["files_checked"]}],
                "Every file in the package matches its signed hash.",
            ))

    update_url = package.get("update_url")
    if isinstance(update_url, str) and update_url.rstrip("/") != STORE_UPDATE_URL:
        review.append(make_indicator(
            "M108", "non_store_update_url", "review",
            [{"update_url": update_url}],
            "The extension updates from somewhere other than the Chrome "
            "Web Store, so its code can change without store review.",
        ))

    return review, trust


def run_metadata_rules(metadata_report):
    if not isinstance(metadata_report, dict):
        raise TypeError("metadata_report must be a dictionary")

    result = copy.deepcopy(metadata_report)

    source = _section(result, "source")
    listing_available = source.get("listing_available")
    if listing_available is None:
        listing_available = source.get("store_listing") not in (None, "package_only")

    review = []
    trust = []

    if listing_available:
        r, t = _listing_rules(result)
        review += r
        trust += t

    if isinstance(result.get("package"), dict):
        r, t = _package_rules(result)
        review += r
        trust += t

    review.sort(key=lambda item: item["rule_id"])
    trust.sort(key=lambda item: item["rule_id"])

    analysis = result.get("analysis")
    if not isinstance(analysis, dict):
        analysis = {}
        result["analysis"] = analysis
    analysis["review_indicators"] = review
    analysis["trust_indicators"] = trust
    existing = analysis.get("limitations")
    if not isinstance(existing, list):
        existing = []
    analysis["limitations"] = list(dict.fromkeys(existing + LIMITATIONS))
    return result


def run_cross_rules(manifest_report, metadata_report):
    if not isinstance(manifest_report, dict) or not isinstance(metadata_report, dict):
        raise TypeError("both reports must be dictionaries")

    metadata_analysis = _section(metadata_report, "analysis")
    if not isinstance(metadata_analysis.get("review_indicators"), list):
        metadata_report = run_metadata_rules(metadata_report)
        metadata_analysis = _section(metadata_report, "analysis")

    manifest_analysis = _section(manifest_report, "analysis")
    manifest_types = {
        item.get("type") for item in manifest_analysis.get("review_indicators", [])
        if isinstance(item, dict)
    }
    metadata_types = {
        item.get("type") for item in metadata_analysis.get("review_indicators", [])
        if isinstance(item, dict)
    }

    indicators = []

    broad = sorted(manifest_types & BROAD_ACCESS_TYPES)
    weak = sorted(metadata_types & WEAK_TRUST_TYPES)

    if broad and len(weak) >= 2:
        indicators.append(make_indicator(
            "C001", "broad_access_with_weak_trust_signals", "review",
            [{"manifest_indicators": broad, "metadata_indicators": weak}],
            "The extension declares broad website access and its store "
            "listing shows several weak trust signals. Check whether the "
            "access fits its stated purpose; neither fact alone is a problem.",
        ))

    sensitive = [
        item.get("permission")
        for item in _section(manifest_report, "permissions").get(
            "sensitive_capabilities", [])
        if isinstance(item, dict) and item.get("permission")
    ]
    missing_privacy = sorted(metadata_types & {"no_privacy_policy", "no_data_disclosure"})

    if sensitive and missing_privacy:
        indicators.append(make_indicator(
            "C002", "sensitive_permissions_without_privacy_information", "review",
            [{"sensitive_permissions": sorted(set(sensitive)),
              "metadata_indicators": missing_privacy}],
            "The extension requests sensitive permissions but its listing "
            "gives no privacy policy or data disclosure. Review what data "
            "those permissions can reach.",
        ))

    return indicators


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(
        description="Run the metadata rules on an extension.")
    parser.add_argument(
        "source",
        help="package (.zip or folder), store URL, or extension ID")
    parser.add_argument(
        "--package", help="package to analyze alongside a store URL or ID")
    parser.add_argument(
        "--offline", action="store_true", help="no network; package only")
    parser.add_argument(
        "--no-download", action="store_true",
        help="do not download the package for a store URL or ID")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    try:
        try:
            import metadata_analyzer as analyzer
        except ImportError:
            from analyzer import metadata_analyzer as analyzer
    except ImportError as exc:
        print(json.dumps({"error": f"Could not import the metadata analyzer: {exc}"},
                         indent=2), file=sys.stderr)
        return 1

    try:
        report = analyzer.build_metadata_report(
            args.source,
            package_path=args.package,
            offline=args.offline,
            download=not args.no_download,
        )
        print(json.dumps(run_metadata_rules(report), indent=2, ensure_ascii=False))
        return 0
    except (OSError, ValueError, TypeError,
            analyzer.ListingUnavailable, analyzer.PackageError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())