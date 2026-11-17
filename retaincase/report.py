import json
from pathlib import Path
from .store import connect


def _run_contract(db, run_id):
    row = db.execute('SELECT * FROM run_jurisdiction WHERE run_id=?', (run_id,)).fetchone()
    if not row:
        return None
    return {'contract': row['contract'], 'authority': row['authority'],
            'as_of': row['as_of'], 'snapshot_digest': row['snapshot_digest'],
            'snapshot': json.loads(row['snapshot'])}


def _jurisdiction_view(db, run_id):
    """Per-subject, per-jurisdiction proof used by the report and verify."""
    view = {}
    for row in db.execute('SELECT * FROM jurisdiction_evidence WHERE run_id=? ORDER BY subject,jurisdiction', (run_id,)):
        item = dict(row)
        policy_body = json.loads(item.pop('policy_body')) if item.get('policy_body') else None
        view.setdefault(item['subject'], []).append({
            'jurisdiction': item['jurisdiction'],
            'applicability': item['applicability'],
            'basis': item['basis'],
            'policy': ({'id': item['policy_id'], 'body': policy_body,
                        'digest': item['policy_digest'],
                        'effective_from': item['effective_from'],
                        'effective_until': item['effective_until']} if item['policy_id'] else None),
            'start': ({'kind': item['start_kind'], 'at': item['start_value'],
                       'event_key': item['start_event_key'],
                       'event_id': item['start_event_id']} if item['start_value'] else None),
            'expires_on': item['expires_on'],
            'expired': None if item['expired'] is None else bool(item['expired']),
            'evidence_gap': item['evidence_gap'],
            'succession': ({'basis': item['succession_basis'],
                            'event_key': item['succession_event_key'],
                            'event_id': item['succession_event_id']}
                           if item['succession_event_key'] else None),
            'exclusion_basis': item['exclusion_basis'],
        })
    return view


def export(db_path, out):
    db = connect(db_path)
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    run = db.execute('SELECT * FROM run ORDER BY id DESC LIMIT 1').fetchone()
    if not run:
        raise ValueError('no_run')
    rid = run['id']
    data = {
        'run': dict(run),
        'contract': _run_contract(db, rid),
        'sources': [{'id': x['id'], 'name': x['name'], 'digest': x['digest']}
                    for x in db.execute('SELECT * FROM source_file ORDER BY id')],
        'decisions': [dict(x) for x in db.execute('SELECT * FROM decision WHERE run_id=? ORDER BY subject', (rid,))],
        'issues': [dict(x) for x in db.execute('SELECT * FROM issue WHERE run_id=? OR run_id IS NULL ORDER BY id', (rid,))],
        'evidence': [dict(x) for x in db.execute('SELECT * FROM evidence WHERE run_id=? ORDER BY id', (rid,))],
        'jurisdictions': _jurisdiction_view(db, rid),
    }
    data['executions'] = [dict(x) for x in db.execute('SELECT * FROM execution ORDER BY id')]
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')

    lines = ['# 离线判定报告', '', f'运行 {rid}：{run["status"]}']
    if data['contract']:
        lines.append(f'\n法域责任合同：{data["contract"]["contract"]}（依据：{data["contract"]["authority"]}，'
                     f'as_of {data["contract"]["as_of"]}，快照 {data["contract"]["snapshot_digest"][:12]}）')
    lines.append('')
    for decision in data['decisions']:
        lines.append(f'- {decision["subject"]}: {decision["status"]}')
        for item in data['jurisdictions'].get(decision['subject'], []):
            policy = item['policy']
            start = item['start']
            label = (f'  - {item["jurisdiction"]} [{item["applicability"]}] '
                     f'{item["basis"]}')
            if policy:
                label += f'；政策 {policy["id"]} 起点={start["kind"] if start else (policy["body"] or {}).get("start")}'
                if policy['effective_from'] or policy['effective_until']:
                    label += (f' 生效=[{policy["effective_from"] or "-"}, '
                              f'{policy["effective_until"] or "-"})')
            if start:
                label += f'；起点事件 {start["event_key"]}@{start["at"]}'
                label += f'；届满 {item["expires_on"]}（{"已届满" if item["expired"] else "未届满"}）'
            if item['evidence_gap']:
                label += f'；缺口 {item["evidence_gap"]}'
            if item['succession']:
                label += (f'；承接证明 {item["succession"]["event_key"]} '
                          f'({item["succession"]["basis"]})')
            if item['exclusion_basis']:
                label += f'；排除依据 {item["exclusion_basis"]}'
            lines.append(label)
    md = out.with_suffix('.md')
    md.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    db.close()
    return out


def verify(db_path):
    db = connect(db_path)
    problems = []
    from .ingest import hash_bytes
    for batch in db.execute('SELECT id,config_raw,config_hash FROM batch'):
        if hash_bytes(batch['config_raw']) != batch['config_hash']:
            problems.append(f'batch_config:{batch["id"]}')
    sources = {s['id']: dict(s) for s in db.execute('SELECT * FROM source_file')}
    for s in sources.values():
        if hash_bytes(s['raw']) != s['digest']:
            problems.append(f'source:{s["id"]}')
    events = {e['id']: dict(e) for e in db.execute('SELECT * FROM raw_event')}
    for e in events.values():
        try:
            lines = sources[e['source_id']]['raw'].decode('utf-8-sig').splitlines()
            original = lines[e['line_no'] - 1]
            if hash_bytes(original.encode('utf-8')) != e['digest'] or json.loads(original) != json.loads(e['payload']):
                problems.append(f'event:{e["id"]}')
        except (KeyError, IndexError, UnicodeError, ValueError):
            problems.append(f'event:{e["id"]}')
    for ev in db.execute('SELECT * FROM evidence WHERE event_id IS NOT NULL'):
        source_event = events.get(ev['event_id'])
        if not source_event or source_event['source_id'] != ev['source_id']:
            problems.append(f'evidence:{ev["id"]}')
    for d in db.execute('SELECT * FROM decision'):
        if not db.execute('SELECT 1 FROM evidence WHERE run_id=? AND subject=?', (d['run_id'], d['subject'])).fetchone():
            problems.append(f'decision:{d["id"]}')
        if db.execute('SELECT 1 FROM raw_event WHERE subject=?', (d['subject'],)).fetchone() and not db.execute(
                'SELECT 1 FROM evidence WHERE run_id=? AND subject=? AND event_id IS NOT NULL', (d['run_id'], d['subject'])).fetchone():
            problems.append(f'decision_source:{d["id"]}')
    # Every frozen jurisdiction row must still point at the source event and
    # policy bytes it claims, and the run contract snapshot must be intact.
    for row in db.execute('SELECT * FROM run_jurisdiction'):
        try:
            if hash_bytes(row['snapshot'].encode('utf-8')) != row['snapshot_digest']:
                problems.append(f'run_jurisdiction:{row["run_id"]}')
            json.loads(row['snapshot'])
        except ValueError:
            problems.append(f'run_jurisdiction:{row["run_id"]}')
    for row in db.execute('SELECT * FROM jurisdiction_evidence'):
        if row['start_event_id'] is not None:
            event = events.get(row['start_event_id'])
            payload = json.loads(event['payload']) if event else {}
            if not event or payload.get('event_key') != row['start_event_key']:
                problems.append(f'jurisdiction_start:{row["id"]}')
        if row['succession_event_id'] is not None:
            event = events.get(row['succession_event_id'])
            payload = json.loads(event['payload']) if event else {}
            if not event or payload.get('event_key') != row['succession_event_key']:
                problems.append(f'jurisdiction_succession:{row["id"]}')
        if row['policy_id']:
            if row['policy_body'] is None:
                problems.append(f'jurisdiction_policy:{row["id"]}')
            else:
                try:
                    body = json.loads(row['policy_body'])
                    digest = hash_bytes(json.dumps(body, sort_keys=True, ensure_ascii=False).encode('utf-8'))
                    if digest != row['policy_digest']:
                        problems.append(f'jurisdiction_policy:{row["id"]}')
                except ValueError:
                    problems.append(f'jurisdiction_policy:{row["id"]}')
    db.close()
    return problems
