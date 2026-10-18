import json
import re
from pathlib import Path

import esprima


# Chrome API namespaces that may expose security-sensitive
# browser or user information.
SENSITIVE_CHROME_APIS = {
    "tabs": "tabs",
    "cookies": "cookies",
    "storage": "storage",
    "history": "history",
    "webRequest": "webRequest",
    "bookmarks": "bookmarks",
    "downloads": "downloads",
    "management": "management",
    "notifications": "notifications",
    "scripting": "scripting",
    "identity": "identity",
}


# Patterns representing potentially sensitive DOM access.
DOM_PATTERNS = {
    "document_cookie": re.compile(
        r"\bdocument\.cookie\b",
        re.IGNORECASE,
    ),

    "password_input": re.compile(
        r"""querySelector(?:All)?\s*\([^)]*password[^)]*\)""",
        re.IGNORECASE,
    ),

    "form_access": re.compile(
        r"\bdocument\.forms\b|\bFormData\s*\(",
        re.IGNORECASE,
    ),

    "input_access": re.compile(
        r"""querySelector(?:All)?\s*\([^)]*(?:input|textarea)[^)]*\)""",
        re.IGNORECASE,
    ),

    "page_content": re.compile(
        r"\b(document\.body|document\.documentElement)"
        r"\.(innerText|textContent|innerHTML)\b",
        re.IGNORECASE,
    ),
}


def make_finding(
    finding_type,
    api_or_pattern,
    file_path,
    line,
    snippet,
):
    """
    Create one standardized analyzer finding.
    """

    return {
        "type": finding_type,
        "api_or_pattern": api_or_pattern,
        "file": str(file_path),
        "line": line,
        "snippet": snippet.strip(),
    }


def walk_ast(node):
    """
    Recursively walk an Esprima AST represented
    as dictionaries and lists.
    """

    if isinstance(node, dict):

        yield node

        for value in node.values():
            yield from walk_ast(value)

    elif isinstance(node, list):

        for item in node:
            yield from walk_ast(item)


def member_expression_to_name(node):
    """
    Convert nested JavaScript member expressions
    into a readable dotted name.

    Example:

        chrome.storage.local.get
    """

    if not isinstance(node, dict):
        return None

    node_type = node.get("type")

    if node_type == "Identifier":
        return node.get("name")

    if node_type != "MemberExpression":
        return None

    left = member_expression_to_name(
        node.get("object")
    )

    if not left:
        return None

    property_node = node.get(
        "property",
        {},
    )

    if node.get("computed"):

        if property_node.get("type") == "Literal":

            right = str(
                property_node.get("value")
            )

        else:
            return None

    else:

        if property_node.get("type") == "Identifier":

            right = property_node.get("name")

        elif property_node.get("type") == "Literal":

            right = str(
                property_node.get("value")
            )

        else:
            return None

    return f"{left}.{right}"


def analyze_dom_access(source, file_path):
    """
    Identify potentially sensitive DOM/user-data access.

    Searches the entire JavaScript source so patterns can
    span multiple lines.
    """

    findings = []

    source_lines = source.splitlines()

    for pattern_name, pattern in DOM_PATTERNS.items():

        for match in pattern.finditer(source):

            # Convert character position to source line number
            line_number = (
                source.count("\n", 0, match.start()) + 1
            )

            # Use the starting source line as the snippet
            if 1 <= line_number <= len(source_lines):
                snippet = source_lines[line_number - 1]
            else:
                snippet = match.group(0)

            findings.append(
                make_finding(
                    "dom_access",
                    pattern_name,
                    file_path,
                    line_number,
                    snippet,
                )
            )

    return findings


def analyze_chrome_apis(source, file_path):
    """
    Parse JavaScript and identify calls
    to sensitive Chrome APIs.
    """

    findings = []

    try:

        tree = esprima.parseScript(
            source,
            loc=True,
            tolerant=True,
        ).toDict()

    except Exception as error:

        findings.append(
            make_finding(
                "parse_error",
                "javascript_parse_error",
                file_path,
                0,
                str(error),
            )
        )

        return findings

    source_lines = source.splitlines()

    for node in walk_ast(tree):

        if node.get("type") != "CallExpression":
            continue

        api_name = member_expression_to_name(
            node.get("callee")
        )

        if not api_name:
            continue

        if not api_name.startswith("chrome."):
            continue

        parts = api_name.split(".")

        if len(parts) < 2:
            continue

        namespace = parts[1]

        if namespace not in SENSITIVE_CHROME_APIS:
            continue

        line_number = (
            node.get("loc", {})
            .get("start", {})
            .get("line", 0)
        )

        if 1 <= line_number <= len(source_lines):

            snippet = source_lines[
                line_number - 1
            ]

        else:

            snippet = ""

        findings.append(
            make_finding(
                "chrome_api",
                api_name,
                file_path,
                line_number,
                snippet,
            )
        )

    return findings


def analyze_js_file(file_path):
    """
    Analyze one JavaScript file for both
    Chrome API usage and DOM access.
    """

    path = Path(file_path)

    source = path.read_text(
        encoding="utf-8",
        errors="ignore",
    )

    findings = []

    findings.extend(
        analyze_chrome_apis(
            source,
            path,
        )
    )

    findings.extend(
        analyze_dom_access(
            source,
            path,
        )
    )

    return findings


def analyze_extension(extension_directory):
    """
    Analyze every JavaScript file
    inside an extension directory.
    """

    extension_directory = Path(
        extension_directory
    )

    if not extension_directory.exists():

        raise FileNotFoundError(
            f"Extension directory does not exist: "
            f"{extension_directory}"
        )

    findings = []

    for js_file in extension_directory.rglob(
        "*.js"
    ):

        findings.extend(
            analyze_js_file(
                js_file
            )
        )

    return findings


if __name__ == "__main__":

    import sys

    if len(sys.argv) != 2:

        print(
            "Usage: python analyzer/access_analyzer.py "
            "<extension_directory>"
        )

        sys.exit(1)

    extension_directory = sys.argv[1]

    try:

        results = analyze_extension(
            extension_directory
        )

        print(
            json.dumps(
                results,
                indent=2,
            )
        )

    except FileNotFoundError as error:

        print(
            json.dumps(
                {
                    "error": str(error)
                },
                indent=2,
            )
        )