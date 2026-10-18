import json
import sys
from pathlib import Path

from access_analyzer import (
    analyze_extension,
    SENSITIVE_CHROME_APIS,
)

from manifest_parser import (
    load_manifest,
    extract_permissions,
)


def get_declared_permissions(manifest):
    """
    Combine required and optional API permissions.
    """

    permission_info = extract_permissions(manifest)

    declared = set(
        permission_info["permissions"]
    )

    declared.update(
        permission_info["optional_permissions"]
    )

    return declared


def get_observed_api_namespaces(findings):
    """
    Extract Chrome API namespaces observed in JavaScript.

    Example:
        chrome.cookies.getAll -> cookies
        chrome.history.search -> history
    """

    observed = set()

    for finding in findings:

        if finding["type"] != "chrome_api":
            continue

        api_name = finding["api_or_pattern"]

        parts = api_name.split(".")

        if len(parts) >= 2:
            observed.add(parts[1])

    return observed


def get_dom_findings(findings):
    """
    Return only DOM/user-data access findings.
    """

    return [
        finding
        for finding in findings
        if finding["type"] == "dom_access"
    ]


def build_access_report(extension_directory):
    """
    Build a structured Person A report describing:

    - declared permissions
    - observed Chrome API namespaces
    - potentially unused permissions
    - observed API namespaces without matching declarations
    - sensitive DOM access
    """

    extension_directory = Path(extension_directory)

    manifest = load_manifest(
        extension_directory
    )

    findings = analyze_extension(
        extension_directory
    )

    declared = get_declared_permissions(
        manifest
    )

    observed = get_observed_api_namespaces(
        findings
    )

    # Only compare permissions represented by namespaces
    # our analyzer currently knows how to track.
    tracked_permissions = set(
        SENSITIVE_CHROME_APIS.values()
    )

    declared_tracked = (
        declared & tracked_permissions
    )

    potentially_unused = (
        declared_tracked - observed
    )

    observed_without_declaration = (
        observed - declared
    )

    return {
        "extension": {
            "name": manifest.get(
                "name",
                "Unknown",
            ),
            "version": manifest.get(
                "version",
                "Unknown",
            ),
        },

        "declared_permissions": sorted(
            declared
        ),

        "observed_api_namespaces": sorted(
            observed
        ),

        "potentially_unused_permissions": sorted(
            potentially_unused
        ),

        "observed_without_matching_declaration": sorted(
            observed_without_declaration
        ),

        "dom_access": get_dom_findings(
            findings
        ),

        "all_findings": findings,

        "analysis_note": (
            "This is a static heuristic analysis. "
            "A potentially unused permission is not "
            "necessarily malicious, and dynamic or "
            "indirect API usage may not be detected."
        ),
    }


if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: python analyzer/access_report.py "
            "<extension_directory>"
        )

        sys.exit(1)

    extension_directory = sys.argv[1]

    try:

        report = build_access_report(
            extension_directory
        )

        print(
            json.dumps(
                report,
                indent=2,
            )
        )

    except Exception as error:

        print(
            json.dumps(
                {
                    "error": str(error)
                },
                indent=2,
            )
        )