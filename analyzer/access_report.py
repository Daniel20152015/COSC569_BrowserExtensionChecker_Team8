import json
import sys
from pathlib import Path

from .access_analyzer import analyze_extension, SENSITIVE_CHROME_APIS
from .manifest_parser import load_manifest, extract_permissions


def get_declared_permissions(manifest):
    """Return the union of required and optional API permissions (legacy field)."""
    permission_info = extract_permissions(manifest)
    return set(permission_info["permissions"]) | set(
        permission_info["optional_permissions"]
    )


def get_observed_api_namespaces(findings):
    """Return the Chrome API namespaces represented by detected calls."""
    observed = set()
    for finding in findings:
        if finding.get("type") != "chrome_api":
            continue
        parts = finding.get("api_or_pattern", "").split(".")
        if len(parts) >= 2 and parts[0] == "chrome":
            observed.add(parts[1])
    return observed


def get_dom_findings(findings):
    """Return potentially sensitive DOM access findings."""
    return [finding for finding in findings if finding.get("type") == "dom_access"]


def build_access_report(extension_directory):
    """Build Person A's evidence report, distinguishing uncertainty and optional access.

    Keeps the existing top-level keys for downstream consumers. An AST parse error
    makes permission non-use conclusions inconclusive even if regex fallback found
    some calls; no runtime behavior is inferred from source-code analysis.
    """
    extension_directory = Path(extension_directory)
    manifest = load_manifest(extension_directory)
    findings = analyze_extension(extension_directory)
    permission_info = extract_permissions(manifest)

    required = set(permission_info["permissions"])
    optional = set(permission_info["optional_permissions"])
    declared = required | optional
    observed = get_observed_api_namespaces(findings)

    tracked_permissions = set(SENSITIVE_CHROME_APIS.values())
    required_tracked = required & tracked_permissions
    optional_tracked = (optional - required) & tracked_permissions
    parse_errors = [
        finding for finding in findings if finding.get("type") == "parse_error"
    ]
    analysis_complete = not parse_errors

    if analysis_complete:
        potentially_unused = required_tracked - observed
        optional_without_observed_usage = optional_tracked - observed
        inconclusive = set()
    else:
        # A parse failure means we cannot rely on the absence of AST matches.
        potentially_unused = set()
        optional_without_observed_usage = set()
        inconclusive = (required_tracked | optional_tracked) - observed

    return {
        "extension": {
            "name": manifest.get("name", "Unknown"),
            "version": manifest.get("version", "Unknown"),
        },
        "declared_permissions": sorted(declared),
        "observed_api_namespaces": sorted(observed),
        "potentially_unused_permissions": sorted(potentially_unused),
        "observed_without_matching_declaration": sorted(observed - declared),
        "dom_access": get_dom_findings(findings),
        "all_findings": findings,
        "analysis_note": (
            "This is a static heuristic analysis. Unobserved API usage does not "
            "prove a permission is unnecessary or an extension is malicious. "
            "Optional permissions may be requested later. Some Chrome API calls "
            "do not require a same-named permission. Dynamic or indirect API "
            "usage may not be detected. A parse error makes non-use inconclusive."
        ),
        # Additional explicit fields; original keys above are preserved.
        "required_permissions": sorted(required),
        "optional_permissions": sorted(optional),
        "host_permissions": sorted(set(permission_info["host_permissions"])),
        "optional_host_permissions": sorted(
            set(permission_info["optional_host_permissions"])
        ),
        "optional_permissions_without_observed_usage": sorted(
            optional_without_observed_usage
        ),
        "analysis_complete": analysis_complete,
        "analysis_status": "complete" if analysis_complete else "partial",
        "parse_errors": parse_errors,
        "inconclusive_permissions": sorted(inconclusive),
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyzer/access_report.py <extension_directory>")
        sys.exit(1)

    try:
        print(json.dumps(build_access_report(sys.argv[1]), indent=2))
    except Exception as error:
        print(json.dumps({"error": str(error)}, indent=2))
        sys.exit(1)
