"""Freeze synthetic ingestion incidents and possible reprocessing actions."""
import hashlib
import json
from pathlib import Path

from .store import connect


def register(db_path, batch_id, source_path):
    if not isinstance(batch_id, str) or not batch_id:
        raise ValueError('bad_repair_batch_id')
    raw = Path(source_path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    body = json.loads(raw)
    if not isinstance(body, dict) or not isinstance(body.get('incidents'), list) \
            or not isinstance(body.get('options'), list) or not body['incidents'] or not body['options']:
        raise ValueError('bad_repair_batch')
    incidents = []
    incident_ids = set()
    for item in body['incidents']:
        incident_id, subject, stage = (item[k] for k in ('incident_id', 'subject', 'stage'))
        if any(not isinstance(x, str) or not x for x in (incident_id, subject, stage)) \
                or incident_id in incident_ids:
            raise ValueError('bad_repair_incident')
        incidents.append((batch_id, incident_id, subject, stage))
        incident_ids.add(incident_id)
    options = []
    option_ids = set()
    for item in body['options']:
        option_id, cost, covers = (item[k] for k in ('option_id', 'cost_cents', 'covers'))
        if not isinstance(option_id, str) or not option_id or option_id in option_ids \
                or type(cost) is not int or cost < 0 or not isinstance(covers, list) \
                or not covers or len(covers) != len(set(covers)) \
                or any(x not in incident_ids for x in covers):
            raise ValueError('bad_repair_option')
        options.append((batch_id, option_id, cost, json.dumps(sorted(covers))))
        option_ids.add(option_id)
    db = connect(db_path)
    try:
        with db:
            parent = db.execute('SELECT id FROM batch LIMIT 1').fetchone()
            if not parent:
                raise ValueError('initialize_first')
            old = db.execute('SELECT source_hash FROM repair_batch WHERE id=?', (batch_id,)).fetchone()
            if old:
                if old['source_hash'] != digest:
                    raise ValueError('repair_batch_identity_conflict')
                return digest
            for _, _, subject, _ in incidents:
                if not db.execute('SELECT 1 FROM subject WHERE id=? AND batch_id=?',
                                  (subject, parent['id'])).fetchone():
                    raise ValueError('unknown_repair_subject')
            db.execute('INSERT INTO repair_batch VALUES (?,?,?,?)',
                       (batch_id, parent['id'], digest, raw))
            db.executemany('INSERT INTO repair_incident VALUES (?,?,?,?)', incidents)
            db.executemany('INSERT INTO repair_option VALUES (?,?,?,?)', options)
            return digest
    finally:
        db.close()


def summary(db_path, batch_id):
    """Raw incident/action census only, without a remediation plan."""
    db = connect(db_path)
    try:
        row = db.execute('SELECT source_hash FROM repair_batch WHERE id=?', (batch_id,)).fetchone()
        if not row:
            raise ValueError('unknown_repair_batch')
        incidents = db.execute('SELECT count(*) n FROM repair_incident WHERE batch_id=?',
                               (batch_id,)).fetchone()['n']
        options = db.execute('SELECT count(*) n FROM repair_option WHERE batch_id=?',
                             (batch_id,)).fetchone()['n']
        return {'incidents': incidents, 'options': options, 'source_hash': row['source_hash']}
    finally:
        db.close()
