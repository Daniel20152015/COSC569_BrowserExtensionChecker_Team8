"""Run manifest, access, network and (optionally) metadata analysis together."""
import argparse
import json
import tempfile
import zipfile
from pathlib import Path

from analyzer import manifestanalyzer, manifestruleengine, access_report, access_rules
from analyzer import network_analyzer, metadata_analyzer, metadata_rules
from risk_scorer import score_report
from llm_report import generate_narrative, fallback_narrative, save_html

MAX_FILES = 5000
MAX_UNCOMPRESSED_BYTES = 250 * 1024 * 1024
MAX_FILE_BYTES = 30 * 1024 * 1024


def unpack_safely(archive_path, destination):
    """Unpack a ZIP without path traversal, symlinks or excessive expansion."""
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_FILES or sum(i.file_size for i in infos) > MAX_UNCOMPRESSED_BYTES:
            raise ValueError('ZIP exceeds file count or uncompressed size limit')
        for info in infos:
            name = info.filename.replace('\\', '/')
            parts = name.split('/')
            if (name.startswith('/') or any(part in ('..', '') for part in parts if part != parts[-1])
                    or '..' in parts or ':' in parts[0] or info.file_size > MAX_FILE_BYTES
                    or (info.external_attr >> 16) & 0o170000 == 0o120000):
                raise ValueError(f'Unsafe ZIP member: {name}')
            target = destination.joinpath(*parts)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as src, target.open('wb') as dst:
                    remaining = info.file_size
                    while remaining:
                        chunk = src.read(min(65536, remaining))
                        if not chunk:
                            raise ValueError('Unexpected end of ZIP member')
                        dst.write(chunk)
                        remaining -= len(chunk)
    if (destination / 'manifest.json').is_file():
        return destination
    candidates = list(destination.glob('*/manifest.json'))
    if len(candidates) == 1:
        return candidates[0].parent
    raise ValueError('Expected exactly one manifest.json at root or one enclosing folder')


def run_checks(root, metadata_source=None, offline=True):
    root = Path(root)
    manifest = manifestanalyzer.read_manifest_file(root / 'manifest.json')
    manifest_result = manifestruleengine.run_manifest_rules(manifestanalyzer.analyze_manifest(manifest))
    report = {
        'schema_version': '1.0',
        'extension': manifest_result['extension'],
        'manifest': manifest_result,
        'access': None,
        'network': None,
        'metadata': None,
        'cross_indicators': [],
        'errors': [],
        'limitations': ['Static analysis does not establish actual runtime behavior or malicious intent.'],
    }
    try:
        report['access'] = access_rules.run_access_rules(access_report.build_access_report(root))
    except Exception as exc:
        report['errors'].append({'component': 'access', 'error': str(exc)})
    try:
        network_findings = network_analyzer.analyze_extension(root)
        report['network'] = {
            'findings': network_findings,
            'analysis_status': 'partial' if any(f.get('type') == 'parse_error' for f in network_findings) else 'complete',
            'limitations': ['Network and data-flow matches are heuristic, not verified exfiltration.'],
        }
    except Exception as exc:
        report['errors'].append({'component': 'network', 'error': str(exc)})
    if metadata_source:
        try:
            metadata = metadata_analyzer.build_metadata_report(
                metadata_source, package_path=root, offline=offline, download=False)
            report['metadata'] = metadata_rules.run_metadata_rules(metadata)
            report['cross_indicators'] = metadata_rules.run_cross_rules(manifest_result, report['metadata'])
        except Exception as exc:
            report['errors'].append({'component': 'metadata', 'error': str(exc)})
    report['analysis_status'] = 'partial' if report['errors'] or any(
        section and section.get('analysis_status') == 'partial'
        for section in (report['access'], report['network'])
    ) else 'complete'
    return report


def main():
    parser = argparse.ArgumentParser(description='Static security review of a Chrome extension')
    parser.add_argument('extension', help='Unpacked extension folder or .zip package')
    parser.add_argument('--store', help='Chrome Web Store URL or 32-letter extension ID for metadata comparison')
    parser.add_argument('--online', action='store_true', help='Fetch store listing when --store is provided')
    parser.add_argument('--output', default='security_report.json', help='Original structured analysis JSON path')
    parser.add_argument('--html', default='security_report.html', help='Readable HTML report path')
    parser.add_argument('--narrative-output', default='narrative_report.json', help='Structured narrative JSON path')
    parser.add_argument('--llm', action='store_true', help='Use OpenAI API for narrative (requires OPENAI_API_KEY; sends full JSON report)')
    parser.add_argument('--model', default='gpt-4.1-mini', help='OpenAI model for --llm')
    args = parser.parse_args()
    try:
        path = Path(args.extension)
        with tempfile.TemporaryDirectory(prefix='extension_scan_') as tmp:
            root = path if path.is_dir() else unpack_safely(path, Path(tmp))
            report = run_checks(root, metadata_source=args.store, offline=not args.online)
            report['risk_assessment'] = score_report(report)
            Path(args.output).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
            if args.llm:
                narrative, llm_error = generate_narrative(report, model=args.model)
                llm_status = 'OpenAI API' if llm_error is None else 'Fallback (OpenAI unavailable)'
                if llm_error:
                    print('Narrative warning:', llm_error)
            else:
                narrative = fallback_narrative(report)
                llm_status = 'Local deterministic narrative (no API call)'
            narrative_doc = {
                'generator': llm_status,
                'score': report['risk_assessment'],
                'narrative': narrative,
            }
            Path(args.narrative_output).write_text(json.dumps(narrative_doc, indent=2, ensure_ascii=False), encoding='utf-8')
            save_html(args.html, report, narrative, llm_status)
        print(f'Report saved to {args.output} (status: {report["analysis_status"]})')
        print(f'HTML report: {args.html}')
        print(f'Structured narrative: {args.narrative_output}')
        if report['errors']:
            print('Component errors:', json.dumps(report['errors'], indent=2))
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        parser.exit(1, f'Error: {exc}\n')


if __name__ == '__main__':
    main()
