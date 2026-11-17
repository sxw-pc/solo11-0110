"""Custody transfer with frozen obligations, per-object receipts and two-party acknowledgement."""
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
# A receipt row is an immutable, append-only fact about one receive (or attempted
# receive) event. 'received' rows are evidence that the recipient actually holds an
# object; disputed/rejected rows never overwrite that evidence and never move custody
# on their own. Nothing in this subsystem ever UPDATEs or DELETEs custody_receipt rows.

def _utc(value):
    dt=datetime.fromisoformat(value.replace('Z','+00:00'))
    if dt.tzinfo is None: raise ValueError('handoff_timezone_required')
    return dt.astimezone(timezone.utc)

def _event_digest(event_key, subject, recipient, received_hash, at):
    payload={'event_key':event_key,'subject':subject,'recipient':recipient,
             'sha256':received_hash,'at':at}
    return hashlib.sha256(json.dumps(payload,sort_keys=True,ensure_ascii=False).encode()).hexdigest()

def _backfill_legacy_accepted(db):
    """Obligation-hash-identical accepted transfers created before per-object receipts
    existed are still whole-transfer proof; record each frozen object once so every
    custody answer reads the same append-only table."""
    rows=db.execute("""SELECT t.id,i.subject,i.expected_hash,t.recipient
      FROM custody_transfer t JOIN custody_item i ON i.transfer_id=t.id
      WHERE t.state='accepted' AND NOT EXISTS(
        SELECT 1 FROM custody_receipt r WHERE r.transfer_id=t.id AND r.verdict='received')""").fetchall()
    for row in rows:
        event_key=f'__legacy_ack__:{row["id"]}:{row["subject"]}'
        db.execute("""INSERT OR IGNORE INTO custody_receipt
          (transfer_id,event_key,subject,recipient,received_hash,event_hash,at,verdict,reason)
          VALUES (?,?,?,?,?,?,?,?,?)""",
          (row['id'],event_key,row['subject'],row['recipient'],row['expected_hash'],'',
           datetime.now(timezone.utc).isoformat(),'received','legacy_accepted_transfer_backfill'))

def object_custody(db, subject, run_id):
    """Custody of one object as of the given adjudication run, read only from receipt
    evidence. Returns (state, detail) where state is 'received', 'disputed' or 'local'.

    'local' means no receipt moved the object off local custody — including objects
    whose only receipt attempts were structurally rejected. Expiry never deletes a
    'received' row, so actual reception survives an expired transfer."""
    rows=db.execute("""SELECT r.*,t.run_id AS transfer_run,t.expires_at
      FROM custody_receipt r JOIN custody_transfer t ON t.id=r.transfer_id
      WHERE r.subject=? ORDER BY r.rowid""",(subject,)).fetchall()
    received=[r for r in rows if r['verdict']=='received']
    disputed=[r for r in rows if r['verdict']=='disputed']
    if received:
        runs={r['transfer_run'] for r in received}
        if runs != {run_id}:
            return 'investigate',{'reason':'received_under_different_run','receipt_runs':sorted(runs),'run_id':run_id}
        if len({r['transfer_id'] for r in received})>1:
            return 'investigate',{'reason':'multiple_accepted_transfers','transfers':sorted({r['transfer_id'] for r in received})}
        return 'received',{'transfer':received[-1]['transfer_id'],'event_key':received[-1]['event_key']}
    if disputed:
        latest=disputed[-1]
        return 'disputed',{'transfer':latest['transfer_id'],'event_key':latest['event_key'],'reason':latest['reason']}
    return 'local',{'reason':'no_receipt_evidence'}

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
        # Only objects still under a LOCAL erase duty block a fresh handoff: handing
        # off an object another recipient already holds (remote_erase) is a legitimate
        # new transfer, and the post-freeze receive rejection in receive() relies on a
        # new handoff being preparable while the frozen request stays open.
        pending=db.execute("""SELECT r.id FROM erasure_request r JOIN erasure_item i ON i.request_id=r.id
          WHERE i.subject=? AND i.obligation='erase' AND r.state!='fulfilled'
          ORDER BY r.id LIMIT 1""",(subject,)).fetchone()
        if pending: raise ValueError(f'pending_erasure_request:{subject}:{pending["id"]}')
        decision=db.execute('SELECT status FROM decision WHERE run_id=? AND subject=?',(run['id'],subject)).fetchone()
        if not decision or decision['status']=='证据不足': raise ValueError(f'cannot_transfer_uncertain:{subject}')
        if db.execute("SELECT 1 FROM execution WHERE subject=? AND action='destroy'",(subject,)).fetchone():
            raise ValueError(f'already_destroyed:{subject}')
        expected=config['subjects'][subject].get('sha256','')
        if not expected: raise ValueError(f'object_hash_required:{subject}')
        items.append((subject,decision['status'],expected))
    obligations={'recipient':recipient,'run_id':run['id'],'config_hash':batch['config_hash'],
                 'items':items,'expires_at':expiry.isoformat()}
    digest=hashlib.sha256(json.dumps(obligations,sort_keys=True).encode()).hexdigest()
    old=db.execute('SELECT obligation_hash FROM custody_transfer WHERE id=?',(transfer_id,)).fetchone()
    if old:
        if old['obligation_hash'] != digest: raise ValueError('handoff_identity_conflict')
        db.close();return inspect(db_path,transfer_id)
    with db:
        db.execute('INSERT INTO custody_transfer VALUES (?,?,?,?,?,?,?)',
                   (transfer_id,batch['id'],run['id'],recipient,expiry.isoformat(),digest,'prepared'))
        db.executemany('INSERT INTO custody_item VALUES (?,?,?,?)',
                       ((transfer_id,*item) for item in items))
    db.close();return inspect(db_path,transfer_id)

def receive(db_path, transfer_id, recipient, event_key, receipts, at):
    """Record the objects the recipient actually received under one receive event.

    Each object gets its own immutable receipt row. Replaying the identical event is
    a no-op; reusing the event key with different content is rejected. Objects absent
    from the event stay in local custody — the transfer's overall state can never be
    used to infer their handoff. Already-confirmed objects cannot be rewritten.

    Late-receive policy (chosen route): once an erasure request covering an object has
    been frozen, a receive for that object is REJECTED ('erasure_request_frozen'); the
    frozen local obligation stands and a new handoff is required. The receive event is
    still registered as a rejected, traceable fact."""
    if not isinstance(receipts,list) or not receipts:
        raise ValueError('receipts_required')
    if not event_key or not recipient.strip():
        raise ValueError('invalid_receive_identity')
    now=_utc(at);at_iso=now.isoformat()
    db=connect(db_path);db.executescript(SCHEMA)
    from .requests import SCHEMA as REQUEST_SCHEMA
    db.executescript(REQUEST_SCHEMA)
    db.execute('BEGIN IMMEDIATE')
    try:
        row=db.execute('SELECT * FROM custody_transfer WHERE id=?',(transfer_id,)).fetchone()
        if not row: raise ValueError('unknown_transfer')
        frozen={x['subject']:x for x in db.execute(
            'SELECT * FROM custody_item WHERE transfer_id=?',(transfer_id,)).fetchall()}
        latest_run=db.execute('SELECT max(id) FROM run').fetchone()[0]
        seen=set()
        for receipt in receipts:
            subject=receipt.get('subject');received_hash=receipt.get('sha256')
            if not subject or not received_hash or subject in seen:
                raise ValueError('incomplete_or_duplicate_receipt')
            seen.add(subject)
        # The event key binds the WHOLE event payload (recipient, timestamp and the
        # exact receipt set). A replay must be byte-identical; adding or dropping an
        # object under the same key is an event-key reuse, not a new submission.
        prior=db.execute('SELECT subject,recipient,received_hash,at FROM custody_receipt WHERE transfer_id=? AND event_key=?',
                         (transfer_id,event_key)).fetchall()
        if prior:
            incoming={(s,recipient,h,at_iso) for s,h in ((r.get('subject'),r.get('sha256')) for r in receipts)}
            stored={(r['subject'],r['recipient'],r['received_hash'],r['at']) for r in prior}
            if incoming != stored:
                raise ValueError('receive_event_identity_conflict')
        for receipt in receipts:
            subject=receipt.get('subject');received_hash=receipt.get('sha256')
            digest=_event_digest(event_key,subject,recipient,received_hash,at_iso)
            if db.execute('SELECT 1 FROM custody_receipt WHERE transfer_id=? AND event_key=? AND subject=?',
                          (transfer_id,event_key,subject)).fetchone():
                continue  # identical replay: immutable evidence, no rewrite
            item=frozen.get(subject)
            # Order matters: identity/run/expiry/manifest rejection first, then the
            # frozen-request gate, and only an unblocked in-manifest object reaches the
            # hash check that can produce a 'disputed' custody state.
            if recipient != row['recipient']:
                verdict,reason='rejected','recipient_mismatch'
            elif latest_run != row['run_id']:
                verdict,reason='rejected','adjudication_run_changed'
            elif now > _utc(row['expires_at']):
                verdict,reason='rejected','transfer_expired'
            elif item is None:
                verdict,reason='rejected','subject_not_in_frozen_manifest'
            elif db.execute("""SELECT 1 FROM erasure_item i JOIN erasure_request r ON r.id=i.request_id
                WHERE i.subject=? AND i.obligation='erase' AND r.state!='fulfilled'
                ORDER BY r.id LIMIT 1""",(subject,)).fetchone():
                # Route A: an object whose frozen duty is a LOCAL erase cannot leave
                # local custody after the freeze; require a new handoff cycle instead.
                # remote_erase objects are already externally held, so a replacement
                # transfer receipt neither rewrites the frozen duty nor is blocked.
                verdict,reason='rejected','erasure_request_frozen'
            elif received_hash != item['expected_hash']:
                verdict,reason='disputed','received_hash_mismatch'
            else:
                verdict,reason='received','matched_frozen_object'
            db.execute("""INSERT INTO custody_receipt
              (transfer_id,event_key,subject,recipient,received_hash,event_hash,at,verdict,reason)
              VALUES (?,?,?,?,?,?,?,?,?)""",
              (transfer_id,event_key,subject,recipient,received_hash,digest,at_iso,verdict,reason))
        # Whole-transfer acceptance follows only from per-object reception evidence.
        missing=db.execute("""SELECT 1 FROM custody_item i WHERE i.transfer_id=? AND NOT EXISTS(
          SELECT 1 FROM custody_receipt r WHERE r.transfer_id=i.transfer_id
          AND r.subject=i.subject AND r.verdict='received') LIMIT 1""",(transfer_id,)).fetchone()
        if not missing and row['state']=='prepared':
            db.execute("UPDATE custody_transfer SET state='accepted' WHERE id=?",(transfer_id,))
        db.commit()
    except Exception:
        db.rollback();raise
    finally:
        db.close()
    return inspect(db_path,transfer_id)

def acknowledge(db_path, transfer_id, recipient, received_hashes, at):
    """An acknowledgement is bound to the exact frozen run and all item bytes.

    Its verdict is additionally persisted as per-object receipt evidence, so custody
    answers never depend on the single whole-transfer state. Disputed/expired
    acknowledgements register rejected or disputed facts instead of moving objects."""
    now=_utc(at);db=connect(db_path);db.executescript(SCHEMA)
    row=db.execute('SELECT * FROM custody_transfer WHERE id=?',(transfer_id,)).fetchone()
    if not row: raise ValueError('unknown_transfer')
    if row['state']=='accepted':
        db.close();return inspect(db_path,transfer_id)
    if row['state']!='prepared': raise ValueError('handoff_not_prepared')
    items=db.execute('SELECT * FROM custody_item WHERE transfer_id=?',(transfer_id,)).fetchall()
    same=(recipient==row['recipient'] and set(received_hashes)=={x['subject'] for x in items}
          and all(received_hashes[x['subject']]==x['expected_hash'] for x in items)
          and db.execute('SELECT max(id) FROM run').fetchone()[0]==row['run_id'])
    state='expired' if now>_utc(row['expires_at']) else ('accepted' if same else 'disputed')
    latest_run=db.execute('SELECT max(id) FROM run').fetchone()[0]
    at_iso=now.isoformat()
    with db:
        db.execute('UPDATE custody_transfer SET state=? WHERE id=?',(state,transfer_id))
        for item in items:
            subject=item['subject'];received_hash=received_hashes.get(subject,'')
            event_key=f'__ack__:{transfer_id}:{subject}'
            digest=_event_digest(event_key,subject,recipient,received_hash,at_iso)
            if now>_utc(row['expires_at']):
                verdict,reason='rejected','transfer_expired'
            elif recipient != row['recipient']:
                verdict,reason='rejected','recipient_mismatch'
            elif latest_run != row['run_id']:
                verdict,reason='rejected','adjudication_run_changed'
            elif subject not in received_hashes:
                verdict,reason='rejected','missing_from_acknowledgement'
            elif received_hash != item['expected_hash']:
                verdict,reason='disputed','received_hash_mismatch'
            else:
                verdict,reason='received','matched_frozen_object'
            db.execute("""INSERT OR IGNORE INTO custody_receipt
              (transfer_id,event_key,subject,recipient,received_hash,event_hash,at,verdict,reason)
              VALUES (?,?,?,?,?,?,?,?,?)""",
              (transfer_id,event_key,subject,recipient,received_hash,digest,at_iso,verdict,reason))
    db.close();return inspect(db_path,transfer_id)

def inspect(db_path,transfer_id):
    db=connect(db_path);db.executescript(SCHEMA)
    row=db.execute('SELECT * FROM custody_transfer WHERE id=?',(transfer_id,)).fetchone()
    if not row:raise ValueError('unknown_transfer')
    _backfill_legacy_accepted(db);db.commit()
    items=[]
    for item in db.execute('SELECT * FROM custody_item WHERE transfer_id=? ORDER BY subject',(transfer_id,)):
        entries=[dict(r) for r in db.execute(
            'SELECT event_key,subject,recipient,received_hash,at,verdict,reason FROM custody_receipt WHERE transfer_id=? AND subject=? ORDER BY rowid',
            (transfer_id,item['subject']))]
        if any(e['verdict']=='received' for e in entries):
            receipt_state='received'
        elif any(e['verdict']=='disputed' for e in entries):
            receipt_state='disputed'
        else:
            receipt_state='pending'
        line=dict(item);line['receipt_state']=receipt_state;line['receipts']=entries
        items.append(line)
    states={x['receipt_state'] for x in items}
    if states=={'received'}: overall='complete'
    elif 'disputed' in states: overall='disputed'
    elif 'received' in states: overall='partial'
    else: overall='none'
    # Receipts for subjects outside the frozen manifest cannot affect object custody,
    # but the rejected attempts stay visible so every submission is traceable.
    manifest={x['subject'] for x in items}
    other=[dict(r) for r in db.execute(
        'SELECT event_key,subject,recipient,received_hash,at,verdict,reason FROM custody_receipt WHERE transfer_id=? ORDER BY rowid',
        (transfer_id,)) if r['subject'] not in manifest]
    result={'transfer':transfer_id,'recipient':row['recipient'],'run_id':row['run_id'],
            'state':row['state'],'obligation_hash':row['obligation_hash'],
            'receipt_state':overall,'items':items,'other_receipts':other}
    db.close();return result
