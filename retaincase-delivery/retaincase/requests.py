"""Multi-object erasure obligations, separate from retention disposition."""
import hashlib
import json
from datetime import datetime, timezone

from .store import connect

SCHEMA = """
CREATE TABLE IF NOT EXISTS erasure_request(
 id TEXT PRIMARY KEY, batch_id TEXT NOT NULL REFERENCES batch(id), due_at TEXT NOT NULL,
 run_id INTEGER NOT NULL REFERENCES run(id), request_hash TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('ready','partial','deferred','uncertain','fulfilled')));
CREATE TABLE IF NOT EXISTS erasure_item(
 request_id TEXT NOT NULL REFERENCES erasure_request(id), subject TEXT NOT NULL REFERENCES subject(id),
 obligation TEXT NOT NULL, evidence TEXT NOT NULL, PRIMARY KEY(request_id,subject));
"""

def _time(value):
    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError('request_timezone_required')
    return dt.astimezone(timezone.utc)

def triage(db_path, request_id, subjects, due_at):
    """Freeze a request and give each object its own disposition obligation."""
    due = _time(due_at)
    ids = sorted(set(subjects))
    if not ids or len(ids) != len(subjects):
        raise ValueError('empty_or_duplicate_subjects')
    db = connect(db_path)
    db.executescript(SCHEMA)
    from .handoff import SCHEMA as HANDOFF_SCHEMA
    db.executescript(HANDOFF_SCHEMA)
    run = db.execute("SELECT * FROM run ORDER BY id DESC LIMIT 1").fetchone()
    if not run:
        raise ValueError('evaluate_first')
    batch = db.execute('SELECT * FROM batch WHERE id=?', (run['batch_id'],)).fetchone()
    digest = hashlib.sha256(json.dumps([ids, due.isoformat(), batch['config_hash']], sort_keys=True).encode()).hexdigest()
    old = db.execute('SELECT * FROM erasure_request WHERE id=?', (request_id,)).fetchone()
    if old:
        if old['request_hash'] != digest:
            raise ValueError('request_identity_conflict')
        return describe(db_path, request_id)
    lines = []
    for subject in ids:
        if not db.execute('SELECT 1 FROM subject WHERE id=? AND batch_id=?', (subject, batch['id'])).fetchone():
            raise ValueError(f'unknown_request_subject:{subject}')
        decision = db.execute('SELECT status,detail FROM decision WHERE run_id=? AND subject=?', (run['id'], subject)).fetchone()
        transfers = db.execute("SELECT t.id FROM custody_transfer t JOIN custody_item i ON i.transfer_id=t.id WHERE i.subject=? AND t.state='accepted' ORDER BY t.id", (subject,)).fetchall()
        transferred = transfers[0] if len(transfers)==1 else None
        if len(transfers)>1 or not decision or decision['status'] == '证据不足':
            obligation = 'investigate'
        elif transferred and decision['status'] == '可销毁':
            obligation = 'remote_erase'
        elif decision['status'] == '可销毁':
            obligation = 'erase'
        else:
            obligation = 'defer'
        lines.append((subject, obligation, json.dumps({'run_id':run['id'], 'decision':dict(decision) if decision else None, 'custody_transfer': transferred['id'] if transferred else None, 'accepted_transfer_count':len(transfers)}, ensure_ascii=False)))
    kinds = {line[1] for line in lines}
    actionable={'erase','remote_erase'}
    state = 'uncertain' if 'investigate' in kinds else ('ready' if kinds<=actionable else ('deferred' if kinds == {'defer'} else 'partial'))
    if due < datetime.now(timezone.utc) and state != 'ready':
        state = 'uncertain'  # overdue obligations require an explicit review
    with db:
        db.execute('INSERT INTO erasure_request VALUES (?,?,?,?,?,?)', (request_id,batch['id'],due.isoformat(),run['id'],digest,state))
        db.executemany('INSERT INTO erasure_item VALUES (?,?,?,?)', ((request_id,*line) for line in lines))
    db.close()
    return describe(db_path, request_id)

def fulfill(db_path, request_id):
    """A missing file is not proof of erasure; require the execution ledger."""
    db = connect(db_path); db.executescript(SCHEMA)
    request = db.execute('SELECT * FROM erasure_request WHERE id=?', (request_id,)).fetchone()
    if not request:
        raise ValueError('unknown_request')
    latest = db.execute('SELECT max(id) FROM run').fetchone()[0]
    if latest != request['run_id']:
        raise ValueError('request_decision_stale')
    items = db.execute('SELECT * FROM erasure_item WHERE request_id=?', (request_id,)).fetchall()
    from .recall import SCHEMA as RECALL_SCHEMA
    db.executescript(RECALL_SCHEMA)
    missing = [r['subject'] for r in items if r['obligation']=='erase' and not db.execute(
        "SELECT 1 FROM execution WHERE subject=? AND action='destroy' AND run_id=?", (r['subject'],latest)).fetchone()]
    missing_remote=[r['subject'] for r in items if r['obligation']=='remote_erase' and not db.execute(
        """SELECT 1 FROM custody_recall c JOIN recall_item i ON i.recall_id=c.id
           WHERE c.request_id=? AND c.run_id=? AND c.state='completed'
           AND i.subject=? AND i.state='confirmed'""",(request_id,latest,r['subject'])).fetchone()]
    if missing or missing_remote:
        db.close();return {'request':request_id,'state':request['state'],
                           'missing_execution':missing,'missing_remote_receipt':missing_remote}
    state = 'fulfilled' if all(r['obligation'] in ('erase','remote_erase') for r in items) else request['state']
    with db:
        db.execute('UPDATE erasure_request SET state=? WHERE id=?', (state,request_id))
    db.close()
    return describe(db_path,request_id)

def describe(db_path, request_id):
    db=connect(db_path);db.executescript(SCHEMA)
    row=db.execute('SELECT * FROM erasure_request WHERE id=?',(request_id,)).fetchone()
    if not row: raise ValueError('unknown_request')
    items=[dict(x) for x in db.execute('SELECT * FROM erasure_item WHERE request_id=? ORDER BY subject',(request_id,))]
    result={'request':request_id,'state':row['state'],'due_at':row['due_at'],'run_id':row['run_id'],'items':items}
    db.close();return result

def subject_release_gate(db, subject, run_id):
    """Decide whether one internal subject may enter a controlled derived package.

    Legal-hold (冻结) subjects may participate without touching the original evidence. Destroyed
    subjects cannot be re-exported from an old inventory; 证据不足 subjects can never pose as
    usable records.
    """
    if not db.execute('SELECT 1 FROM subject WHERE id=?', (subject,)).fetchone():
        raise ValueError(f'unknown_subject:{subject}')
    decision = db.execute('SELECT status FROM decision WHERE run_id=? AND subject=?',
                          (run_id, subject)).fetchone()
    if not decision:
        return {'eligible': False, 'reason': 'decision_missing', 'status': None}
    status = decision['status']
    if status == '证据不足':
        return {'eligible': False, 'reason': 'decision_uncertain', 'status': status}
    destroyed = db.execute(
        "SELECT 1 FROM execution WHERE subject=? AND action='destroy' LIMIT 1",
        (subject,)).fetchone()
    if destroyed:
        return {'eligible': False, 'reason': 'already_destroyed', 'status': status}
    return {'eligible': True,
            'reason': 'legal_hold_controlled' if status == '冻结' else 'retained_available',
            'status': status}

def freeze_delivery(db_path, request_id, inventory_id, recipient, purpose, route, spec, package_dir):
    """Entry point on the requests module; delegates the package engine to delivery."""
    from .delivery import freeze
    return freeze(db_path, request_id, inventory_id, recipient, purpose, route, spec, package_dir)

def resume_delivery(db_path, request_id, package_dir):
    from .delivery import _resume
    return _resume(db_path, request_id, package_dir)

def verify_delivery(db_path, request_id, package_dir):
    from .delivery import verify
    return verify(db_path, request_id, package_dir)

def delivery_report(db_path, request_id):
    from .delivery import report
    return report(db_path, request_id)
