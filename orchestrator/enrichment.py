"""Normalize LLM enrichment payloads for Splunk alert analysis."""
from typing import Any, Dict, List


def _clamp_weight(value: Any, default: float = 0.75) -> float:
    try:
        weight = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, weight))


def _clamp_confidence(value: Any, default: float = 85.0) -> float:
    try:
        conf = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(100.0, conf))


def normalize_timeline(items: Any, fallback_time: str = '--:--') -> List[dict]:
    if not isinstance(items, list):
        return []
    timeline = []
    for index, item in enumerate(items):
        if isinstance(item, str):
            text = item.strip()
            if text:
                timeline.append({
                    'time': fallback_time,
                    'label': f'Stage {index + 1}',
                    'detail': text,
                    'mitre': '',
                })
        elif isinstance(item, dict):
            detail = str(item.get('detail') or item.get('description') or '').strip()
            if not detail:
                continue
            timeline.append({
                'time': str(item.get('time') or fallback_time).strip() or fallback_time,
                'label': str(item.get('label') or item.get('stage') or f'Stage {index + 1}').strip(),
                'detail': detail,
                'mitre': str(item.get('mitre') or item.get('technique') or '').strip(),
            })
    return timeline


def normalize_evidence(items: Any, alert_id: str, source_ip: str, dest_ip: str, signature: str) -> List[dict]:
    if not isinstance(items, list):
        items = []
    evidence = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        signal = str(item.get('signal') or item.get('description') or '').strip()
        if not signal:
            continue
        evidence.append({
            'id': str(item.get('id') or f'EV-{alert_id}-{index + 1}'),
            'type': str(item.get('type') or 'network').strip().lower(),
            'src': str(item.get('src') or source_ip).strip(),
            'signal': signal,
            'weight': _clamp_weight(item.get('weight')),
        })

    if not evidence:
        evidence = [
            {
                'id': f'EV-{alert_id}-NET-SRC',
                'type': 'network',
                'src': source_ip,
                'signal': signature or 'Suricata IDS match',
                'weight': 0.88,
            },
            {
                'id': f'EV-{alert_id}-NET-DST',
                'type': 'network',
                'src': dest_ip,
                'signal': f'Flow involving {dest_ip}',
                'weight': 0.76,
            },
        ]
    return evidence


def normalize_mitre(items: Any) -> List[dict]:
    if not isinstance(items, list):
        return []
    techniques = []
    for item in items:
        if isinstance(item, str):
            tid = item.strip()
            if tid:
                techniques.append({'id': tid, 'tactic': 'Unknown', 'name': tid})
        elif isinstance(item, dict):
            tid = str(item.get('id') or item.get('technique_id') or '').strip()
            if not tid:
                continue
            techniques.append({
                'id': tid,
                'tactic': str(item.get('tactic') or 'Unknown').strip(),
                'name': str(item.get('name') or tid).strip(),
            })
    return techniques


def normalize_soar_actions(items: Any, containment_steps: List[str], source_ip: str, dest_ip: str) -> List[dict]:
    if isinstance(items, list) and items:
        actions = []
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            action = str(item.get('action') or '').strip()
            if not action:
                continue
            actions.append({
                'id': str(item.get('id') or f'A{index + 1}'),
                'action': action,
                'target': str(item.get('target') or source_ip).strip(),
                'reason': str(item.get('reason') or action).strip(),
                'confidence': _clamp_confidence(item.get('confidence')),
                'impact': str(item.get('impact') or 'Pending analyst execution').strip(),
            })
        if actions:
            return actions

    # Fallback: derive from containment checklist strings
    actions = []
    for index, step in enumerate(containment_steps):
        lower = step.lower()
        if 'block' in lower:
            action_name = 'Block IP'
            target = dest_ip if dest_ip != 'unknown' else source_ip
        elif 'isolate' in lower:
            action_name = 'Isolate Host'
            target = source_ip
        elif 'disable' in lower:
            action_name = 'Disable Account'
            target = source_ip
        else:
            action_name = 'Contain'
            target = source_ip
        actions.append({
            'id': f'S{index + 1}',
            'action': action_name,
            'target': target,
            'reason': step,
            'confidence': 85.0,
            'impact': 'Pending analyst execution',
        })
    return actions


def build_enrichment(
    data: Dict[str, Any],
    *,
    alert_id: str,
    source_ip: str,
    dest_ip: str,
    signature: str,
    fallback_time: str,
    containment_steps: List[str],
) -> dict:
    timeline = normalize_timeline(
        data.get('attack_timeline') or data.get('timeline'),
        fallback_time=fallback_time,
    )
    if not timeline:
        timeline = [{
            'time': fallback_time,
            'label': 'IDS Alert',
            'detail': f'{signature} · {source_ip} → {dest_ip}',
            'mitre': 'T1071.001',
        }]

    evidence = normalize_evidence(
        data.get('evidence'),
        alert_id=alert_id,
        source_ip=source_ip,
        dest_ip=dest_ip,
        signature=signature,
    )

    mitre = normalize_mitre(data.get('mitre_techniques') or data.get('mitre'))
    if not mitre:
        seen = set()
        for step in timeline:
            tid = step.get('mitre', '').strip()
            if tid and tid not in seen:
                seen.add(tid)
                mitre.append({'id': tid, 'tactic': 'Inferred', 'name': tid})

    actions = normalize_soar_actions(
        data.get('recommended_actions') or data.get('soar_actions'),
        containment_steps=containment_steps,
        source_ip=source_ip,
        dest_ip=dest_ip,
    )

    likelihood = data.get('likelihood')
    try:
        likelihood = max(0.0, min(100.0, float(likelihood)))
    except (TypeError, ValueError):
        likelihood = None

    bullets = data.get('bullets') or data.get('analysis_bullets') or containment_steps
    if isinstance(bullets, str):
        bullets = [line.strip() for line in bullets.splitlines() if line.strip()]
    elif isinstance(bullets, list):
        bullets = [str(b).strip() for b in bullets if str(b).strip()]
    else:
        bullets = list(containment_steps)

    recommendation = str(
        data.get('recommendation') or data.get('primary_recommendation') or ''
    ).strip()
    if not recommendation and actions:
        recommendation = f"{actions[0]['action']} on {actions[0]['target']}: {actions[0]['reason']}"

    return {
        'likelihood': likelihood,
        'timeline': timeline,
        'evidence': evidence,
        'mitre_techniques': mitre,
        'recommended_actions': actions,
        'bullets': bullets,
        'recommendation': recommendation,
    }
