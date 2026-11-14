"""Person A rule engine: turn access-analyzer evidence into review indicators.

This module consumes the dictionary produced by build_access_report().
It does not change the underlying analyzer or make malware/risk verdicts.
The output format matches the team's manifest rule engine:
    report['analysis']['review_indicators'] = [
        {'rule_id', 'type', 'severity', 'evidence', 'explanation'}, ...
    ]

Usage from the repository root:
    python analyzer/access_rules.py samples/clean_extension
    python analyzer/access_rules.py samples/overpermissioned_extension
    python analyzer/access_rules.py samples/suspicious_extension
"""

import copy
import json
import sys
from pathlib import Path


# Generic input selection can be normal extension behavior.  These four
# patterns merit closer review, but do not establish data theft or abuse.
SENSITIVE_DOM_PATTERNS = {
    "document_cookie",
    "password_input",
    "form_access",
    "page_content",
}

LIMITATIONS = [
    "Rules flag source-code evidence for review; they do not prove malicious behavior.",
    "Absence of an observed API call does not prove a permission is unnecessary.",
    "An API namespace may be usable without a same-named permission declaration.",
    "Static DOM detection can have false positives and does not establish data exfiltration.",
]


def make_indicator(rule_id, indicator_type, severity, evidence, explanation):
    """Return a finding in the team's manifest-rule indicator format."""
    return {
        "rule_id": rule_id,
        "type": indicator_type,
        "severity": severity,
        "evidence": evidence,
        "explanation": explanation,
    }


def _strings(value):
    """Deduplicate and sort string values from a report field."""
    if not isinstance(value, (list, tuple, set)):
        return []
    return sorted({x for x in value if isinstance(x, str) and x})


def _findings(value):
    """Keep only well-formed finding dictionaries without mutating them."""
    if not isinstance(value, list):
        return []
    return [copy.deepcopy(x) for x in value if isinstance(x, dict)]


def run_access_rules(access_report):
    """Add review indicators to an existing Person A access report.

    Maintains all existing report fields and is safe to call repeatedly.
    Incomplete parsing blocks rules claiming *unobserved* permissions.
    """
    if not isinstance(access_report, dict):
        raise TypeError("access_report must be a dictionary")

    result = copy.deepcopy(access_report)
    indicators = []

    parse_errors = _findings(result.get("parse_errors"))
    if not parse_errors:
        parse_errors = [
            f for f in _findings(result.get("all_findings"))
            if f.get("type") == "parse_error"
        ]

    # An absent status field is treated as complete for older reports only
    # when no parse error exists. The report generator supplies both fields.
    complete = (
        result.get("analysis_complete", True) is not False
        and result.get("analysis_status", "complete") != "partial"
        and not parse_errors
    )

    if complete:
        required = set(_strings(result.get("required_permissions")))
        unused = _strings(result.get("potentially_unused_permissions"))
        # Only required permissions belong in the required-permission rule.
        if "required_permissions" in result:
            unused = [p for p in unused if p in required]

        if unused:
            indicators.append(make_indicator(
                "A001", "potentially_unused_required_permissions", "review",
                [{"permission": p, "permission_type": "required"} for p in unused],
                "These required permissions were not matched to API calls in "
                "the analyzed code. They may still have legitimate or indirect uses; review them.",
            ))

        optional = _strings(result.get("optional_permissions_without_observed_usage"))
        if optional:
            indicators.append(make_indicator(
                "A002", "optional_permissions_without_observed_usage", "informational",
                [{"permission": p, "permission_type": "optional"} for p in optional],
                "These optional permissions had no observed API calls. "
                "Optional permissions may be requested later and are not necessarily unused.",
            ))

    dom_findings = _findings(result.get("dom_access"))
    if not dom_findings:
        dom_findings = [
            f for f in _findings(result.get("all_findings"))
            if f.get("type") == "dom_access"
        ]
    sensitive_dom = [
        f for f in dom_findings
        if f.get("type") == "dom_access"
        and f.get("api_or_pattern") in SENSITIVE_DOM_PATTERNS
    ]
    if sensitive_dom:
        indicators.append(make_indicator(
            "A003", "sensitive_dom_access", "review", sensitive_dom,
            "The source contains patterns associated with reading cookies, "
            "password fields, forms, or page content. Whether this is appropriate "
            "depends on the extension's purpose; transmission is not established.",
        ))

    undeclared_namespaces = _strings(
        result.get("observed_without_matching_declaration")
    )
    if undeclared_namespaces:
        indicators.append(make_indicator(
            "A004", "api_namespace_without_same_named_declaration", "informational",
            [{"api_namespace": p} for p in undeclared_namespaces],
            "API calls were observed without same-named permission declarations. "
            "This may be valid: not every Chrome API method requires a named permission.",
        ))

    if not complete:
        evidence = [
            {"parse_error": error} for error in parse_errors
        ] + [
            {"inconclusive_permission": p}
            for p in _strings(result.get("inconclusive_permissions"))
        ]
        if not evidence:
            evidence = [{"analysis_status": result.get("analysis_status", "partial")}]
        indicators.append(make_indicator(
            "A005", "incomplete_access_analysis", "review", evidence,
            "At least part of the JavaScript analysis was incomplete. "
            "Do not conclude that unobserved permissions are unused from this scan.",
        ))

    analysis = result.get("analysis")
    if not isinstance(analysis, dict):
        analysis = {}
        result["analysis"] = analysis
    analysis["review_indicators"] = indicators
    existing_limitations = analysis.get("limitations")
    if not isinstance(existing_limitations, list):
        existing_limitations = []
    analysis["limitations"] = list(dict.fromkeys(existing_limitations + LIMITATIONS))
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("Usage: python analyzer/access_rules.py <extension_directory>", file=sys.stderr)
        return 2
    try:
        # Deferred import: pure rule evaluation can be tested independently
        # without requiring the Esprima parser.
        from access_report import build_access_report

        report = run_access_rules(build_access_report(Path(argv[0])))
        print(json.dumps(report, indent=2))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
