import json
from pathlib import Path


def load_manifest(extension_directory):
    """
    Load manifest.json from a Chrome extension directory.
    """

    extension_directory = Path(extension_directory)
    manifest_path = extension_directory / "manifest.json"

    if not manifest_path.exists():
        raise FileNotFoundError(
            f"No manifest.json found in: {extension_directory}"
        )

    with manifest_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def extract_permissions(manifest):
    """
    Extract permission-related fields from manifest.json.
    """

    return {
        "permissions": manifest.get("permissions", []),
        "optional_permissions": manifest.get(
            "optional_permissions", []
        ),
        "host_permissions": manifest.get(
            "host_permissions", []
        ),
        "optional_host_permissions": manifest.get(
            "optional_host_permissions", []
        ),
    }


def summarize_manifest(extension_directory):
    """
    Return basic extension information and requested permissions.
    """

    manifest = load_manifest(extension_directory)

    return {
        "name": manifest.get("name", "Unknown"),
        "version": manifest.get("version", "Unknown"),
        "manifest_version": manifest.get(
            "manifest_version", "Unknown"
        ),
        "permissions": extract_permissions(manifest),
    }


if __name__ == "__main__":
    import pprint
    import sys

    if len(sys.argv) != 2:
        print(
            "Usage: python analyzer/manifest_parser.py "
            "<extension_directory>"
        )
        sys.exit(1)

    extension_directory = sys.argv[1]

    try:
        result = summarize_manifest(
            extension_directory
        )

        pprint.pp(result)

    except (
        FileNotFoundError,
        json.JSONDecodeError,
    ) as error:

        print(f"Error: {error}")