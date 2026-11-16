"""Compatibility layer for the access report's original manifest_parser import."""
import json
from pathlib import Path


def load_manifest(extension_directory):
    path = Path(extension_directory) / 'manifest.json'
    with path.open(encoding='utf-8') as stream:
        manifest = json.load(stream)
    if not isinstance(manifest, dict):
        raise ValueError('manifest.json must contain an object')
    return manifest


def extract_permissions(manifest):
    def strings(key):
        value = manifest.get(key, [])
        return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []
    def host(p):
        return p == '<all_urls>' or '://' in p or p.startswith('file:')
    required = strings('permissions')
    optional = strings('optional_permissions')
    return {
        'permissions': [p for p in required if not host(p)],
        'optional_permissions': [p for p in optional if not host(p)],
        'host_permissions': list(dict.fromkeys(strings('host_permissions') + [p for p in required if host(p)])),
        'optional_host_permissions': list(dict.fromkeys(strings('optional_host_permissions') + [p for p in optional if host(p)])),
    }
