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
    "document_cookie": re.compile(r"\bdocument\.cookie\b", re.IGNORECASE),
    "password_input": re.compile(
        r"""querySelector(?:All)?\s*\([^)]*password[^)]*\)""",
        re.IGNORECASE,
    ),
    "form_access": re.compile(
        r"\bdocument\.forms\b|\bFormData\s*\(", re.IGNORECASE
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


def mask_js_comments(source):
    """Mask // and /* */ comments, preserving positions and line breaks.

    Quoted strings and template text are preserved, so URLs and comment-like
    characters inside them are not treated as comments. This is a lightweight
    scanner, not a full parser of JavaScript template expressions/regex literals.
    """
    result = list(source)
    i = 0
    state = "code"

    while i < len(source):
        char = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""

        if state == "code":
            if char in ("'", '"', "`"):
                state = char
            elif char == "/" and nxt == "/":
                result[i] = result[i + 1] = " "
                i += 2
                state = "line_comment"
                continue
            elif char == "/" and nxt == "*":
                result[i] = result[i + 1] = " "
                i += 2
                state = "block_comment"
                continue
        elif state in ("'", '"', "`"):
            if char == "\\":
                i += 2
                continue
            if char == state:
                state = "code"
        elif state == "line_comment":
            if char in "\r\n":
                state = "code"
            else:
                result[i] = " "
        elif state == "block_comment":
            if char == "*" and nxt == "/":
                result[i] = result[i + 1] = " "
                i += 2
                state = "code"
                continue
            if char not in "\r\n":
                result[i] = " "

        i += 1

    return "".join(result)


def mask_js_strings_and_comments(source):
    """Mask string/template contents as well as comments for fallback scanning."""
    source = mask_js_comments(source)
    result = list(source)
    i = 0
    state = None

    while i < len(source):
        ch = source[i]
        if state is None:
            if ch in ("'", '"', "`"):
                state = ch
                result[i] = " "
        else:
            if ch == "\\":
                if ch not in "\r\n":
                    result[i] = " "
                if i + 1 < len(source):
                    i += 1
                    if source[i] not in "\r\n":
                        result[i] = " "
            elif ch == state:
                result[i] = " "
                state = None
            elif ch not in "\r\n":
                result[i] = " "
        i += 1

    return "".join(result)


def make_finding(finding_type, api_or_pattern, file_path, line, snippet):
    """Create one standardized analyzer finding."""
    return {
        "type": finding_type,
        "api_or_pattern": api_or_pattern,
        "file": str(file_path),
        "line": line,
        "snippet": snippet.strip(),
    }


def walk_ast(node):
    """Recursively walk an Esprima AST represented as dictionaries and lists."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from walk_ast(value)
    elif isinstance(node, list):
        for item in node:
            yield from walk_ast(item)


def member_expression_to_name(node):
    """Convert nested member expressions into dotted names."""
    if not isinstance(node, dict):
        return None

    node_type = node.get("type")
    if node_type == "Identifier":
        return node.get("name")
    if node_type != "MemberExpression":
        return None

    left = member_expression_to_name(node.get("object"))
    if not left:
        return None

    property_node = node.get("property", {})
    if node.get("computed"):
        if property_node.get("type") != "Literal":
            return None
        right = str(property_node.get("value"))
    else:
        if property_node.get("type") == "Identifier":
            right = property_node.get("name")
        elif property_node.get("type") == "Literal":
            right = str(property_node.get("value"))
        else:
            return None

    return f"{left}.{right}"


def analyze_dom_access(source, file_path):
    """Detect potential DOM access without matching comments."""
    findings = []
    source_lines = source.splitlines()
    masked_source = mask_js_comments(source)

    for pattern_name, pattern in DOM_PATTERNS.items():
        for match in pattern.finditer(masked_source):
            line_number = source.count("\n", 0, match.start()) + 1
            snippet = (
                source_lines[line_number - 1]
                if 1 <= line_number <= len(source_lines)
                else match.group(0)
            )
            findings.append(
                make_finding(
                    "dom_access", pattern_name, file_path, line_number, snippet
                )
            )
    return findings


def recover_chrome_api_calls(source, file_path):
    """Best-effort recovery of direct Chrome API calls after a parse failure.

    This is incomplete by design; the caller also emits a parse_error finding.
    """
    findings = []
    masked = mask_js_strings_and_comments(source)
    lines = source.splitlines()
    pattern = re.compile(
        r"\bchrome\.([A-Za-z_$][\w$]*)((?:\.[A-Za-z_$][\w$]*)+)\s*\("
    )

    for match in pattern.finditer(masked):
        namespace = match.group(1)
        if namespace not in SENSITIVE_CHROME_APIS:
            continue
        line_number = source.count("\n", 0, match.start()) + 1
        snippet = lines[line_number - 1] if 1 <= line_number <= len(lines) else ""
        finding = make_finding(
            "chrome_api",
            f"chrome.{namespace}{match.group(2)}",
            file_path,
            line_number,
            snippet,
        )
        finding["detection_method"] = "regex_fallback"
        findings.append(finding)

    return findings


def analyze_chrome_apis(source, file_path):
    """Parse JavaScript and identify calls to sensitive Chrome APIs."""
    findings = []
    try:
        tree = esprima.parseScript(source, loc=True, tolerant=True).toDict()
    except Exception as error:
        findings.append(
            make_finding(
                "parse_error", "javascript_parse_error", file_path, 0, str(error)
            )
        )
        findings.extend(recover_chrome_api_calls(source, file_path))
        return findings

    source_lines = source.splitlines()
    for node in walk_ast(tree):
        if node.get("type") != "CallExpression":
            continue
        api_name = member_expression_to_name(node.get("callee"))
        if not api_name or not api_name.startswith("chrome."):
            continue
        parts = api_name.split(".")
        if len(parts) < 2 or parts[1] not in SENSITIVE_CHROME_APIS:
            continue

        line_number = node.get("loc", {}).get("start", {}).get("line", 0)
        snippet = (
            source_lines[line_number - 1]
            if 1 <= line_number <= len(source_lines)
            else ""
        )
        findings.append(
            make_finding("chrome_api", api_name, file_path, line_number, snippet)
        )
    return findings


def analyze_js_file(file_path):
    """Analyze one JavaScript file for Chrome API usage and DOM access."""
    path = Path(file_path)
    source = path.read_text(encoding="utf-8", errors="ignore")
    return analyze_chrome_apis(source, path) + analyze_dom_access(source, path)


def analyze_extension(extension_directory):
    """Analyze every JavaScript file inside an extension directory."""
    extension_directory = Path(extension_directory)
    if not extension_directory.exists():
        raise FileNotFoundError(
            f"Extension directory does not exist: {extension_directory}"
        )
    findings = []
    for js_file in extension_directory.rglob("*.js"):
        findings.extend(analyze_js_file(js_file))
    return findings


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python analyzer/access_analyzer.py <extension_directory>")
        sys.exit(1)

    try:
        results = analyze_extension(sys.argv[1])
        print(json.dumps(results, indent=2))
    except FileNotFoundError as error:
        print(json.dumps({"error": str(error)}, indent=2))
