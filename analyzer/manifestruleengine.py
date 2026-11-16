from . import manifestanalyzer
import json
import copy

BROAD_HOST_PATTERNS = {
    "<all_urls>",
    "*://*/*",
    "http://*/*",
    "https://*/*"
}


def is_broad_host_pattern(pattern):
    """Check whether a host pattern grants broad website access."""
    return pattern in BROAD_HOST_PATTERNS


def run_manifest_rules(analyzer_output):
    """
    Evaluate the output from the manifest analyzer.

    Returns the original analyzer output with an updated
    analysis section containing rule-engine findings.
    """

    analyzer_output = copy.deepcopy(analyzer_output)
    permissions = analyzer_output.get("permissions", {})
    content_scripts = analyzer_output.get("content_scripts", [])

    if not isinstance(permissions, dict):
        permissions = {}

    if not isinstance(content_scripts, list):
        content_scripts = []

    review_indicators = []

    all_hosts = []
    for key in ("required_host_permissions", "optional_host_permissions"):
        values = permissions.get(key, [])
        if isinstance(values, list):
            all_hosts.extend(v for v in values if isinstance(v, str))

    broad_hosts = permissions.get("broad_host_patterns")

    if not isinstance(broad_hosts, list):
        broad_hosts = [
            host for host in all_hosts
            if isinstance(host, str) and is_broad_host_pattern(host)
        ]

    if broad_hosts:
        review_indicators.append({
            "rule_id": "R001",
            "type": "broad_host_access",
            "severity": "review",
            "evidence": broad_hosts,
            "explanation": (
                "The extension declares broad website access. "
                "Check whether its purpose requires this access."
            )
        })

    broad_script_matches = []

    for index, script in enumerate(content_scripts):

        if not isinstance(script, dict):
            continue

        matches = script.get("matches", [])

        if not isinstance(matches, list):
            continue

        broad_matches = [
            pattern for pattern in matches
            if isinstance(pattern, str)
            and is_broad_host_pattern(pattern)
        ]

        if broad_matches:
            broad_script_matches.append({
                "script_index": index,
                "matches": broad_matches,
                "js_files": script.get("js_files", [])
            })

    if broad_script_matches:
        review_indicators.append({
            "rule_id": "R002",
            "type": "broad_content_script_injection",
            "severity": "review",
            "evidence": broad_script_matches,
            "explanation": (
                "A content script declares broad matching patterns. "
                "Check what information the script accesses on those pages."
            )
        })

    main_world_scripts = []

    for index, script in enumerate(content_scripts):

        if not isinstance(script, dict):
            continue

        world = script.get("world", "ISOLATED")

        if world == "MAIN":
            main_world_scripts.append({
                "script_index": index,
                "js_files": script.get("js_files", []),
                "matches": script.get("matches", [])
            })

    if main_world_scripts:
        review_indicators.append({
            "rule_id": "R003",
            "type": "main_world_execution",
            "severity": "informational",
            "evidence": main_world_scripts,
            "explanation": (
                "A content script runs in the MAIN JavaScript world, "
                "sharing the page's JavaScript environment. "
                "Inspect its interactions with page scripts."
            )
        })

    all_frame_scripts = []

    for index, script in enumerate(content_scripts):

        if not isinstance(script, dict):
            continue

        if script.get("all_frames", False) is True:
            all_frame_scripts.append({
                "script_index": index,
                "js_files": script.get("js_files", []),
                "matches": script.get("matches", [])
            })

    if all_frame_scripts:
        review_indicators.append({
            "rule_id": "R004",
            "type": "all_frame_injection",
            "severity": "informational",
            "evidence": all_frame_scripts,
            "explanation": (
                "A content script is configured to run in all "
                "matching frames, including qualifying embedded frames. "
                "Inspect what information it accesses in those contexts."
            )
        })

    required_permissions = permissions.get(
        "required_api_permissions", []
    )

    optional_permissions = permissions.get(
        "optional_api_permissions", []
    )

    scripting_status = None

    if "scripting" in required_permissions:
        scripting_status = "required"
    elif "scripting" in optional_permissions:
        scripting_status = "optional"

    if scripting_status:
        review_indicators.append({
            "rule_id": "R005",
            "type": "programmatic_scripting",
            "severity": "informational",
            "evidence": [{
                "permission": "scripting",
                "required_or_optional": scripting_status
            }],
            "explanation": (
                "The extension requests the scripting API, which "
                "allows programmatic JavaScript or CSS injection "
                "subject to applicable access restrictions."
            )
        })

    analysis = analyzer_output.setdefault("analysis", {})

    analysis["review_indicators"] = review_indicators


    analysis.setdefault("errors", [])
    analysis.setdefault("warnings", [])

    analysis["limitations"] = [
        "Manifest analysis identifies declarations, not confirmed runtime behavior.",
        "Permission sensitivity does not establish malicious intent.",
        "Review indicators identify behaviors worth investigating, not proof of malicious activity."
    ]

    return analyzer_output

if __name__ == "__main__":

    zip_path = "eimadpbcbfnmbkopoojfekhnkhdbieeh.zip"

    manifest = manifestanalyzer.read_manifest(zip_path)

    result = manifestanalyzer.analyze_manifest(manifest)

    result = run_manifest_rules(result)

    print(json.dumps(result, indent=2))