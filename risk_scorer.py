"""Conservative, reproducible review-priority scoring; not a malware probability."""

WEIGHTS = {
    'broad_host_access': 12,
    'broad_content_script_injection': 8,
    'sensitive_dom_access': 12,
    'potentially_unused_required_permissions': 6,
    'incomplete_access_analysis': 0,
    'extension_id_mismatch': 20,
    'version_mismatch': 15,
    'not_signed_by_webstore': 5,
    'low_rating': 3,
    'stale_listing': 3,
    'no_privacy_policy': 3,
    'no_data_disclosure': 3,
    'collects_user_data': 0,
}
NETWORK_WEIGHTS = {'data_to_network': 18, 'dynamic_code': 8, 'remote_script': 5, 'obfuscation': 4}


def score_report(report):
    """Score unique review signals once per type, with capped network contributions."""
    reasons = []
    points = 0
    for section in ('manifest', 'access', 'metadata'):
        obj = report.get(section) or {}
        analysis = obj.get('analysis') or {}
        seen = set()
        for item in analysis.get('review_indicators', []):
            if not isinstance(item, dict):
                continue
            kind = item.get('type')
            if kind in seen or item.get('severity') != 'review':
                continue
            seen.add(kind)
            weight = WEIGHTS.get(kind, 0)
            if weight:
                points += weight
                reasons.append({'source': section, 'type': kind, 'points': weight, 'rule_id': item.get('rule_id')})
    network = report.get('network') or {}
    seen = set()
    for finding in network.get('findings', []):
        if not isinstance(finding, dict):
            continue
        kind = finding.get('type')
        if kind in seen:
            continue
        seen.add(kind)
        weight = NETWORK_WEIGHTS.get(kind, 0)
        if weight:
            points += weight
            reasons.append({'source': 'network', 'type': kind, 'points': weight, 'file': finding.get('file'), 'line': finding.get('line')})
    points = min(points, 100)
    rating = 'low' if points < 20 else 'moderate' if points < 45 else 'elevated' if points < 70 else 'high'
    return {
        'score': points,
        'rating': rating,
        'meaning': 'Review priority based on static indicators; not a probability of malware or proof of compromise.',
        'policy_version': '1.0',
        'contributors': reasons,
        'confidence_note': 'Incomplete analysis reduces confidence; missing evidence is not evidence of safety.',
    }
