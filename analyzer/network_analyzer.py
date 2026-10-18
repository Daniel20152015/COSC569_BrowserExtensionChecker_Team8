import json
import re
import sys
from pathlib import Path

import esprima

from analyzer.access_analyzer import make_finding, member_expression_to_name
from urllib.parse import urlparse

FUNCS = ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression")

# Where "collected" data comes from
SOURCES = (
    "document.cookie", "localStorage", "sessionStorage",
    "chrome.cookies", "chrome.history", "chrome.tabs",
    "chrome.storage", "chrome.bookmarks",
)


def walk(node, funcs=()):
    """Yield (node, enclosing function names). Names `const f = function(){}` too."""
    if isinstance(node, dict):
        t = node.get("type")
        if t == "VariableDeclarator" and (node.get("init") or {}).get("type") in FUNCS:
            node["init"]["_name"] = (node.get("id") or {}).get("name")
        if t in FUNCS:
            name = (node.get("id") or {}).get("name") or node.get("_name") or "anonymous"
            funcs = funcs + (name,)
        yield node, funcs
        for v in node.values():
            yield from walk(v, funcs)
    elif isinstance(node, list):
        for item in node:
            yield from walk(item, funcs)


def resolve_string(n):
    """Best-effort URL resolution. Unknown pieces become {?}. None = fully unknown."""
    if not isinstance(n, dict):
        return None
    t = n.get("type")
    if t == "Literal" and isinstance(n.get("value"), str):
        return n["value"]
    if t == "TemplateLiteral":
        out = ""
        for i, q in enumerate(n["quasis"]):
            out += q["value"]["cooked"] or ""
            if i < len(n["expressions"]):
                out += "{?}"
        return out
    if t == "BinaryExpression" and n.get("operator") == "+":
        l, r = resolve_string(n["left"]), resolve_string(n["right"])
        if l is None and r is None:
            return None
        return (l if l is not None else "{?}") + (r if r is not None else "{?}")
    return None


def url_details(node):
    raw = resolve_string(node) if node else None
    if raw is None:
        return {"destination": "unresolved"}
    d = {"destination": raw}
    host = urlparse(raw).hostname
    if host:
        d["domain"] = host
    if raw.lower().startswith(("http://", "ws://")):
        d["non_https"] = True
    if re.match(r"^(https?|wss?)://\d{1,3}(\.\d{1,3}){3}", raw):
        d["raw_ip"] = True
    return d


def carries_data(nodes, tainted):
    """True if any node reads a SOURCE or a variable we marked as collected data."""
    for n in nodes:
        for sub, _ in walk(n):
            t = sub.get("type")
            if t == "MemberExpression":
                if (member_expression_to_name(sub) or "").startswith(SOURCES):
                    return True
            elif t == "Identifier" and sub.get("name") in tainted:
                return True
    return False


def collect_taint(tree):
    """Basic file-wide pass: variables/callback params that hold collected data."""
    tainted = set()
    for n, _ in walk(tree):
        t = n.get("type")
        if t == "VariableDeclarator" and n.get("init") and n["id"].get("type") == "Identifier":
            if carries_data([n["init"]], tainted):
                tainted.add(n["id"]["name"])
        elif t == "CallExpression":
            name = member_expression_to_name(n.get("callee")) or ""
            if name.startswith(SOURCES):
                for a in n["arguments"]:
                    if a.get("type") in FUNCS:
                        for p in a["params"]:
                            if p.get("type") == "Identifier":
                                tainted.add(p["name"])
    return tainted


def analyze_file(file_path):
    path = Path(file_path)
    source = path.read_text(encoding="utf-8", errors="ignore")
    lines = source.splitlines()

    try:
        tree = esprima.parseScript(source, loc=True, tolerant=True).toDict()
    except Exception as e:
        return [make_finding("parse_error", "javascript_parse_error", path, 0, str(e))]

    tainted = collect_taint(tree)
    out = []

    def add(kind, pattern, node, funcs, details=None):
        line = node["loc"]["start"]["line"]
        f = make_finding(kind, pattern, path, line,
                         lines[line - 1] if 0 < line <= len(lines) else "")
        f["enclosing_function"] = next((n for n in funcs if n != "anonymous"), "<top-level>")
        f["function_chain"] = list(funcs)
        f["details"] = details or {}
        out.append(f)

    def net(pattern, node, funcs, url_node, args=()):
        d = url_details(url_node)
        add("network_call", pattern, node, funcs, d)
        if args and carries_data(args, tainted):
            add("data_to_network", pattern, node, funcs, d)

    for node, funcs in walk(tree):
        t = node.get("type")

        if t == "CallExpression":
            name = member_expression_to_name(node.get("callee")) or ""
            args = node["arguments"]
            a0 = args[0] if args else None
            a1 = args[1] if len(args) > 1 else None

            if name in ("fetch", "window.fetch"):
                net("fetch", node, funcs, a0, args[1:])
            elif name.endswith("sendBeacon"):
                net("sendBeacon", node, funcs, a0, args[1:])
            elif (name.endswith(".open") and a1 and (a0 or {}).get("type") == "Literal"
                  and str(a0.get("value")).upper() in ("GET", "POST", "PUT", "DELETE", "PATCH")):
                net("XMLHttpRequest.open", node, funcs, a1)
            elif name.endswith(".send") and args and carries_data(args, tainted):
                net("XMLHttpRequest.send", node, funcs, None, args)
            elif name == "importScripts":
                add("remote_script", "importScripts", node, funcs, url_details(a0))
            elif name.endswith("createElement") and (a0 or {}).get("value") in ("script", "img", "iframe"):
                add("remote_script", f"createElement({a0['value']})", node, funcs)
            elif name.endswith("sendMessage") or name.endswith("onMessage.addListener"):
                add("message_passing", name, node, funcs)
            elif name == "eval":
                add("dynamic_code", "eval", node, funcs)
            elif name == "Function":
                add("dynamic_code", "Function()", node, funcs)
            elif name in ("atob", "btoa"):
                add("dynamic_code", name, node, funcs)
            elif name in ("setTimeout", "setInterval") and (a0 or {}).get("type") == "Literal" \
                    and isinstance(a0.get("value"), str):
                add("dynamic_code", f"{name}(string)", node, funcs)

        elif t == "NewExpression":
            name = member_expression_to_name(node.get("callee")) or ""
            if name in ("WebSocket", "EventSource"):
                net(name, node, funcs, node["arguments"][0] if node["arguments"] else None)
            elif name == "Function":
                add("dynamic_code", "new Function", node, funcs)

        elif t == "AssignmentExpression":
            left = node.get("left", {})
            if left.get("type") == "MemberExpression" and \
                    (left.get("property") or {}).get("name") in ("src", "href"):
                add("remote_script", f".{left['property']['name']} =", node, funcs,
                    url_details(node["right"]))

        elif t == "Literal":
            v = node.get("value")
            if isinstance(v, str) and len(v) >= 100 and re.fullmatch(r"[A-Za-z0-9+/=]+", v):
                add("dynamic_code", "base64_blob", node, funcs, {"length": len(v)})

    # Rough file-level obfuscation signals: reasons, not a verdict
    reasons = []
    if lines and len(source) / len(lines) > 300:
        reasons.append("very_long_lines")
    if len(re.findall(r"\\x[0-9a-fA-F]{2}", source)) > 50:
        reasons.append("many_hex_escapes")
    if len(re.findall(r"\b_0x[0-9a-f]+\b", source)) > 20:
        reasons.append("hex_identifiers")
    if reasons:
        f = make_finding("obfuscation", "heuristic", path, 1, "")
        f["enclosing_function"] = "<file>"
        f["details"] = {"reasons": reasons}
        out.append(f)

    return out


def analyze_extension(extension_directory):
    root = Path(extension_directory)
    if not root.exists():
        raise FileNotFoundError(f"Extension directory does not exist: {root}")
    findings = []
    for js in root.rglob("*.js"):
        findings.extend(analyze_file(js))
    return findings


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m analyzer.network_analyzer <extension_directory>")
        sys.exit(1)
    print(json.dumps(analyze_extension(sys.argv[1]), indent=2))