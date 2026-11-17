"""Custody transfer with frozen obligations and two-party acknowledgement."""
import hashlib
import json
from datetime import datetime, timezone

from .store import connect

SCHEMA = """
CREATE TABLE IF NOT EXISTS custody_transfer(
 id TEXT PRIMARY KEY, batch_id TEXT NOT NULL REFERENCES batch(id), run_id INTEGER NOT NULL REFERENCES run(id),
 recipient TEXT NOT NULL, expires_at TEXT NOT NULL, obligation_hash TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('prepared','accepted','disputed','expired')));
CREATE TABLE IF NOT EXISTS custody_item(
 transfer_id TEXT NOT NULL REFERENCES custody_transfer(id), subject TEXT NOT NULL REFERENCES subject(id),
 decision_status TEXT NOT NULL, expected_hash TEXT NOT NULL, PRIMARY KEY(transfer_id,subject));
"""

def _utc(value):
    dt=datetime.fromisoformat(value.replace('Z','+00:00'))
    if dt.tzinfo is None: raise ValueError('handoff_timezone_required')
    return dt.astimezone(timezone.utc)

def prepare(db_path, transfer_id, recipient, subjects, expires_at):
    if not recipient.strip() or not subjects or len(set(subjects)) != len(subjects):
        raise ValueError('invalid_handoff_identity')
    expiry=_utc(expires_at)
    if expiry <= datetime.now(timezone.utc): raise ValueError('handoff_expired')
    db=connect(db_path);db.executescript(SCHEMA)
    from .requests import SCHEMA as REQUEST_SCHEMA
    db.executescript(REQUEST_SCHEMA)
    run=db.execute('SELECT * FROM run ORDER BY id DESC LIMIT 1').fetchone()
    if not run: raise ValueError('evaluate_first')
    batch=db.execute('SELECT * FROM batch WHERE id=?',(run['batch_id'],)).fetchone()
    config=json.loads(batch['config_raw'])
    items=[]
    for subject in sorted(subjects):
        pending=db.execute("SELECT r.id FROM erasure_request r JOIN erasure_item i ON i.request_id=r.id WHERE i.subject=? AND i.obligation IN ('erase','remote_erase') AND r.state!='fulfilled' ORDER BY r.id LIMIT 1",(subject,)).fetchone()
        if pending: raise ValueError(f'pending_erasure_request:{subject}:{pending["id"]}')
        decision=db.execute('SELECT status FROM decision WHERE run_id=? AND subject=?',(run['id'],subject)).fetchone()
        if not decision or decision['status']=='证据不足': raise ValueError(f'cannot_transfer_uncertain:{subject}')
        if db.execute("SELECT 1 FROM execution WHERE subject=? AND action='destroy'",(subject,)).fetchone():
            raise ValueError(f'already_destroyed:{subject}')
        from .execution import blocked_subject
        if blocked_subject(db_path,subject):
            # Local isolation in progress is not a way around remote custody.
            raise ValueError(f'local_execution_in_progress:{subject}')
        expected=config['subjects'][subject].get('sha256','')
        if not expected: raise ValueError(f'object_hash_required:{subject}')
        items.append((subject,decision['status'],expected))
    obligations={'recipient':recipient,'run_id':run['id'],'config_hash':batch['config_hash'],
                 'items':items,'expires_at':expiry.isoformat()}
    digest=hashlib.sha256(json.dumps(obligations,sort_keys=True).encode()).hexdigest()
    old=db.execute('SELECT obligation_hash FROM custody_transfer WHERE id=?',(transfer_id,)).fetchone()
    if old:
        if old['obligation_hash'] != digest: raise ValueError('handoff_identity_conflict')
        return inspect(db_path,transfer_id)
    with db:
        db.execute('INSERT INTO custody_transfer VALUES (?,?,?,?,?,?,?)',
                   (transfer_id,batch['id'],run['id'],recipient,expiry.isoformat(),digest,'prepared'))
        db.executemany('INSERT INTO custody_item VALUES (?,?,?,?)',
                       ((transfer_id,*item) for item in items))
    db.close();return inspect(db_path,transfer_id)

def acknowledge(db_path, transfer_id, recipient, received_hashes, at):
    """An acknowledgement is bound to the exact frozen run and all item bytes."""
    now=_utc(at);db=connect(db_path);db.executescript(SCHEMA)
    row=db.execute('SELECT * FROM custody_transfer WHERE id=?',(transfer_id,)).fetchone()
    if not row: raise ValueError('unknown_transfer')
    if row['state']=='accepted': return inspect(db_path,transfer_id)
    if row['state']!='prepared': raise ValueError('handoff_not_prepared')
    items=db.execute('SELECT * FROM custody_item WHERE transfer_id=?',(transfer_id,)).fetchall()
    same=(recipient==row['recipient'] and set(received_hashes)=={x['subject'] for x in items}
          and all(received_hashes[x['subject']]==x['expected_hash'] for x in items)
          and db.execute('SELECT max(id) FROM run').fetchone()[0]==row['run_id'])
    state='expired' if now>_utc(row['expires_at']) else ('accepted' if same else 'disputed')
    with db:db.execute('UPDATE custody_transfer SET state=? WHERE id=?',(state,transfer_id))
    db.close();return inspect(db_path,transfer_id)

def inspect(db_path,transfer_id):
    db=connect(db_path);db.executescript(SCHEMA)
    row=db.execute('SELECT * FROM custody_transfer WHERE id=?',(transfer_id,)).fetchone()
    if not row:raise ValueError('unknown_transfer')
    result={'transfer':transfer_id,'recipient':row['recipient'],'run_id':row['run_id'],
            'state':row['state'],'obligation_hash':row['obligation_hash'],
            'items':[dict(x) for x in db.execute('SELECT * FROM custody_item WHERE transfer_id=? ORDER BY subject',(transfer_id,))]}
    db.close();return result
