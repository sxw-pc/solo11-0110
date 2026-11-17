"""Freeze local access scans for retained subjects without session inference."""
import hashlib
import json
from pathlib import Path

from .store import connect
from .timeline import instant


def register(db_path, log_id, source_path):
    raw = Path(source_path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if not log_id:
        raise ValueError('bad_usage_log_id')
    rows = []
    for line in raw.decode('utf-8').splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        event_id, subject, actor, device, action, at, error = (item[k] for k in
            ('event_id', 'subject', 'actor', 'device', 'action', 'reported_at', 'error_seconds'))
        instant(at)
        if not all(isinstance(x, str) and x for x in (event_id, subject, actor, device)) \
                or action not in ('enter', 'exit') or type(error) is not int or error < 0:
            raise ValueError('bad_usage_scan')
        rows.append((log_id, event_id, subject, actor, device, action, at, error))
    if not rows or len({r[1] for r in rows}) != len(rows):
        raise ValueError('duplicate_or_empty_usage_scans')
    db = connect(db_path)
    try:
        with db:
            batch = db.execute('SELECT id FROM batch LIMIT 1').fetchone()
            if not batch:
                raise ValueError('initialize_first')
            old = db.execute('SELECT source_hash FROM usage_log WHERE id=?', (log_id,)).fetchone()
            if old:
                if old['source_hash'] != digest:
                    raise ValueError('usage_log_identity_conflict')
                return digest
            for row in rows:
                if not db.execute('SELECT 1 FROM subject WHERE id=? AND batch_id=?',
                                  (row[2], batch['id'])).fetchone():
                    raise ValueError('unknown_usage_subject')
            db.execute('INSERT INTO usage_log VALUES (?,?,?,?)', (log_id, batch['id'], digest, raw))
            db.executemany('INSERT INTO usage_scan VALUES (?,?,?,?,?,?,?,?)', rows)
            return digest
    finally:
        db.close()


def summary(db_path, log_id):
    """Raw scan counts only; no pairing or clock correction."""
    db = connect(db_path)
    try:
        if not db.execute('SELECT 1 FROM usage_log WHERE id=?', (log_id,)).fetchone():
            raise ValueError('unknown_usage_log')
        scans = db.execute('SELECT count(*) n FROM usage_scan WHERE log_id=?', (log_id,)).fetchone()['n']
        actors = db.execute('SELECT count(DISTINCT actor) n FROM usage_scan WHERE log_id=?',
                            (log_id,)).fetchone()['n']
        devices = db.execute('SELECT count(DISTINCT device) n FROM usage_scan WHERE log_id=?',
                             (log_id,)).fetchone()['n']
        return {'scans': scans, 'actors': actors, 'devices': devices}
    finally:
        db.close()
