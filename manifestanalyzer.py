
import json
import zipfile
from pathlib import Path


# Permissions worth highlighting for further review.
SENSITIVE_PERMISSIONS = {
    "cookies": "Cookie access",
    "history": "Browsing history access",
    "debugger": "Browser debugging access",
    "clipboardRead": "Clipboard read access",
    "clipboardWrite": "Clipboard write access",
    "downloads": "Download management",
    "management": "Extension and app management",
    "nativeMessaging": "Communication with native applications",
    "webRequest": "Network request observation",
    "webRequestBlocking": "Blocking or modifying requests where supported",
    "proxy": "Browser proxy configuration",
    "geolocation": "Location access",
    "scripting": "Programmatic script injection capability",
    "tabCapture": "Tab content capture",
    "desktopCapture": "Screen or window capture",
    "history": "Browsing history access",
}

# Manifest keys extracted explicitly by this analyzer.
EXTRACTED_FIELDS = {
    "manifest_version",
    "name",
    "short_name",
    "version",
    "version_name",
    "description",
    "author",
    "homepage_url",
    "update_url",
    "minimum_chrome_version",
    "default_locale",
    "icons",
    "permissions",
    "optional_permissions",
    "host_permissions",
    "optional_host_permissions",
    "content_scripts",
    "background",
    "action",
    "browser_action",
    "page_action",
    "web_accessible_resources",
    "externally_connectable",
    "content_security_policy",
    "declarative_net_request",
    "options_page",
    "options_ui",
    "devtools_page",
    "commands",
    "side_panel",
    "sandbox",
    "incognito",
    "chrome_settings_overrides",
    "chrome_url_overrides",
    "oauth2",
    "storage",
    "key",
}


def read_manifest(zip_path):
    """Read manifest.json from the root of a ZIP package."""
    try:
        with zipfile.ZipFile(zip_path, "r") as archive:
            names = archive.namelist()

            if "manifest.json" not in names:
                raise ValueError(
                    "manifest.json was not found at the ZIP root. "
                    "The ZIP may contain an enclosing directory."
                )

            info = archive.getinfo("manifest.json")

            if info.file_size > 5 * 1024 * 1024:
                raise ValueError("Manifest exceeds the 5 MB size limit.")

            with archive.open(info) as file:
                manifest = json.load(file)

    except zipfile.BadZipFile as exc:
        raise ValueError("The supplied file is not a valid ZIP.") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON at line {exc.lineno}, "
            f"column {exc.colno}: {exc.msg}"
        ) from exc

    if not isinstance(manifest, dict):
        raise ValueError("The manifest must be a JSON object.")

    return manifest


def analyze_manifest(manifest):
    # Extract security-relevant metadata and basic indicators.

    errors = []
    warnings = []

    manifest_version = manifest.get("manifest_version")

    if manifest_version not in (2, 3):
        errors.append("Missing or unsupported manifest_version.")

    for field in ("name", "version"):
        if not isinstance(manifest.get(field), str):
            errors.append(f"Missing or invalid {field}.")

    def get_list(field):
        value = manifest.get(field, [])

        if not isinstance(value, list):
            errors.append(f"{field} must be a list.")
            return []

        if not all(isinstance(item, str) for item in value):
            errors.append(f"{field} must contain only strings.")
            return []

        return value

    permissions = get_list("permissions")
    optional_permissions = get_list("optional_permissions")
    host_permissions = get_list("host_permissions")
    optional_hosts = get_list("optional_host_permissions")

    # Manifest V2 may declare host patterns in permissions.
    permission_hosts = [
        item for item in permissions
        if item == "<all_urls>"
        or "://" in item
        or item.startswith("file:")
    ]

    api_permissions = [
        item for item in permissions
        if item not in permission_hosts
    ]

    all_permissions = list(dict.fromkeys(
        api_permissions + optional_permissions
    ))

    sensitive_findings = []

    for permission in all_permissions:
        if permission in SENSITIVE_PERMISSIONS:
            sensitive_findings.append({
                "permission": permission,
                "required_or_optional": (
                    "required" if permission in api_permissions
                    else "optional"
                ),
                "meaning": SENSITIVE_PERMISSIONS[permission]
            })

    # Detect broad host patterns without treating them as proof of misuse.
    all_hosts = list(dict.fromkeys(
        permission_hosts + host_permissions + optional_hosts
    ))

    broad_hosts = [
        host for host in all_hosts
        if host in ("<all_urls>", "*://*/*",
                    "http://*/*", "https://*/*")
    ]

    # Extract content script configuration.
    content_scripts = manifest.get("content_scripts", [])

    if not isinstance(content_scripts, list):
        errors.append("content_scripts must be a list.")
        content_scripts = []

    scripts = []

    for index, entry in enumerate(content_scripts):
        if not isinstance(entry, dict):
            errors.append(
                f"content_scripts[{index}] must be an object."
            )
            continue

        scripts.append({
            "matches": entry.get("matches", []),
            "exclude_matches": entry.get("exclude_matches", []),
            "include_globs": entry.get("include_globs", []),
            "exclude_globs": entry.get("exclude_globs", []),
            "js_files": entry.get("js", []),
            "css_files": entry.get("css", []),
            "all_frames": entry.get("all_frames", False),
            "match_about_blank": entry.get("match_about_blank", False),
            "match_origin_as_fallback":
                entry.get("match_origin_as_fallback", False),
            "run_at": entry.get("run_at", "document_idle"),
            "world": entry.get("world", "ISOLATED")
        })

    background = manifest.get("background", {})
    if not isinstance(background, dict):
        errors.append("background must be an object.")
        background = {}

    # Preserve all manifest keys this analyzer does not explicitly handle.
    additional_fields = {
        key: value
        for key, value in manifest.items()
        if key not in EXTRACTED_FIELDS
    }

    # Basic indicators for human or downstream review.
    indicators = []

    if broad_hosts:
        indicators.append({
            "type": "broad_host_access",
            "severity": "review",
            "evidence": broad_hosts,
            "explanation":
                "The extension declares broad website access. "
                "Check whether its purpose requires this access."
        })

    if any(
        script["matches"] == ["<all_urls>"]
        or "*://*/*" in script["matches"]
        or "https://*/*" in script["matches"]
        for script in scripts
    ):
        indicators.append({
            "type": "broad_content_script_injection",
            "severity": "review",
            "explanation":
                "A content script declares broad matching patterns."
        })

    if manifest.get("externally_connectable"):
        indicators.append({
            "type": "external_messaging_configured",
            "severity": "review",
            "evidence": manifest["externally_connectable"],
            "explanation":
                "Review which websites or extensions may message "
                "this extension and how incoming messages are handled."
        })

    if manifest.get("web_accessible_resources"):
        indicators.append({
            "type": "web_accessible_resources_declared",
            "severity": "informational",
            "evidence": manifest["web_accessible_resources"],
            "explanation":
                "Review which packaged resources are exposed and "
                "which origins or extensions can access them."
        })

    return {
        "extension": {
            "name": manifest.get("name"),
            "short_name": manifest.get("short_name"),
            "version": manifest.get("version"),
            "version_name": manifest.get("version_name"),
            "description": manifest.get("description"),
            "author": manifest.get("author"),
            "homepage_url": manifest.get("homepage_url"),
            "update_url": manifest.get("update_url"),
            "minimum_chrome_version":
                manifest.get("minimum_chrome_version"),
            "default_locale": manifest.get("default_locale"),
            "manifest_version": manifest_version,
            "icons": manifest.get("icons")
        },
        "permissions": {
            "required_api_permissions": api_permissions,
            "optional_api_permissions": optional_permissions,
            "required_host_permissions":
                list(dict.fromkeys(permission_hosts + host_permissions)),
            "optional_host_permissions": optional_hosts,
            "sensitive_capabilities": sensitive_findings,
            "broad_host_patterns": broad_hosts
        },
        "content_scripts": scripts,
        "background": {
            "service_worker": background.get("service_worker"),
            "scripts": background.get("scripts"),
            "type": background.get("type"),
            "persistent": background.get("persistent")
        },
        "network_and_messaging": {
            "declarative_net_request":
                manifest.get("declarative_net_request"),
            "web_accessible_resources":
                manifest.get("web_accessible_resources"),
            "externally_connectable":
                manifest.get("externally_connectable")
        },
        "security_configuration": {
            "content_security_policy":
                manifest.get("content_security_policy"),
            "sandbox": manifest.get("sandbox"),
            "incognito": manifest.get("incognito"),
            "key_present": "key" in manifest
        },
        "user_interface": {
            "action": manifest.get("action"),
            "browser_action": manifest.get("browser_action"),
            "page_action": manifest.get("page_action"),
            "options_page": manifest.get("options_page"),
            "options_ui": manifest.get("options_ui"),
            "side_panel": manifest.get("side_panel"),
            "devtools_page": manifest.get("devtools_page"),
            "commands": manifest.get("commands")
        },
        "other_configuration": {
            "chrome_settings_overrides":
                manifest.get("chrome_settings_overrides"),
            "chrome_url_overrides":
                manifest.get("chrome_url_overrides"),
            "oauth2": manifest.get("oauth2"),
            "storage": manifest.get("storage")
        },
        "additional_manifest_fields": additional_fields,
        "analysis": {
            "basic_structure_valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "review_indicators": indicators,
            "limitations": [
                "Manifest analysis identifies declarations, not "
                "confirmed runtime behavior.",
                "Permission sensitivity does not establish malicious intent."
            ]
        }
    }


if __name__ == "__main__":
    zip_path = "oedkbkpngfmjfbmmmijkogojlcddmcgf.zip"

    try:
        manifest = read_manifest(zip_path)
        result = analyze_manifest(manifest)
        print(json.dumps(result, indent=2, ensure_ascii=False))

    except (ValueError, OSError) as exc:
        print(f"Could not analyze extension: {exc}")
