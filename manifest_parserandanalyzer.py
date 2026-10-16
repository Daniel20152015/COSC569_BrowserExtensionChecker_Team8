import json
import zipfile
from pathlib import Path

def read_manifest(zip_path):
    with zipfile.ZipFile(zip_path, "r") as archive:
        # Find the manifest at the package root.
        if "manifest.json" not in archive.namelist():
            raise ValueError(
                "manifest.json was not found at the ZIP root"
            )

        with archive.open("manifest.json") as file:
            manifest = json.load(file)

    return manifest

def analyze_manifest(manifest):

    # Extract the relevant manifest fields.
    permissions = manifest.get("permissions", [])
    optional_permissions = manifest.get("optional_permissions", [])
    host_permissions = manifest.get("host_permissions", [])
    optional_hosts = manifest.get("optional_host_permissions", [])
    content_scripts = manifest.get("content_scripts", [])

    # Extract content script details.
    scripts = []
    for entry in content_scripts:
        scripts.append({
            "matches": entry.get("matches", []),
            "js_files": entry.get("js", []),
            "all_frames": entry.get("all_frames", False)
        })

    # Flag potentially sensitive capabilities.
    sensitive_permissions = {
        "cookies": "Can use the cookies API when access requirements are met",
        "history": "Can access browsing history",
        "tabs": "May access sensitive tab information with applicable access",
        "debugger": "Can interact with the browser debugging interface",
        "webRequest": "Can observe network requests for permitted hosts",
        "clipboardRead": "Can read clipboard contents when permitted"
    }

    findings = []
    for permission in permissions:
        if permission in sensitive_permissions:
            findings.append({
                "permission": permission,
                "meaning": sensitive_permissions[permission]
            })

    return {
        "extension": {
            "name": manifest.get("name"),
            "version": manifest.get("version"),
            "description": manifest.get("description"),
            "manifest_version": manifest.get("manifest_version")
        },
        "permissions": permissions,
        "optional_permissions": optional_permissions,
        "host_permissions": host_permissions,
        "optional_host_permissions": optional_hosts,
        "content_scripts": scripts,
        "background_service_worker":
            manifest.get("background", {}).get("service_worker"),
        "sensitive_capabilities": findings
    }

if __name__ == "__main__":
    manifest = read_manifest("oedkbkpngfmjfbmmmijkogojlcddmcgf.zip")
    result = analyze_manifest(manifest)
    print(json.dumps(result, indent=2))