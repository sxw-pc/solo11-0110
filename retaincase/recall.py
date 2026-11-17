"""Recipient-side erasure receipts for assets previously handed off."""
import hashlib
import hmac
import json

from .store import connect
from .handoff import SCHEMA as HANDOFF_SCHEMA
from .requests import SCHEMA as REQUEST_SCHEMA

SCHEMA = """
CREATE TABLE IF NOT EXISTS custody_recall(
 id TEXT PRIMARY KEY, request_id TEXT NOT NULL REFERENCES erasure_request(id),
 transfer_id TEXT NOT NULL REFERENCES custody_transfer(id), recipient TEXT NOT NULL,
 run_id INTEGER NOT NULL REFERENCES run(id), state TEXT NOT NULL
 CHECK(state IN ('pending','partial','disputed','completed')),
 UNIQUE(request_id,transfer_id));
CREATE TABLE IF NOT EXISTS recall_item(
 recall_id TEXT NOT NULL REFERENCES custody_recall(id), subject TEXT NOT NULL REFERENCES subject(id),
 expected_hash TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','disputed','confirmed')),
 certificate TEXT, PRIMARY KEY(recall_id,subject));
CREATE TABLE IF NOT EXISTS recall_attempt(
 event_key TEXT PRIMARY KEY, recall_id TEXT NOT NULL REFERENCES custody_recall(id),
 subject TEXT NOT NULL, receipt_hash TEXT NOT NULL, verdict TEXT NOT NULL,
 reason TEXT NOT NULL);
"""

def _digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False).encode()).hexdigest()

def open_case(db_path,recall_id,request_id,transfer_id):
    db=connect(db_path);db.executescript(HANDOFF_SCHEMA+REQUEST_SCHEMA+SCHEMA)
    request=db.execute('SELECT * FROM erasure_request WHERE id=?',(request_id,)).fetchone()
    transfer=db.execute('SELECT * FROM custody_transfer WHERE id=?',(transfer_id,)).fetchone()
    if not request or not transfer:raise ValueError('accepted_transfer_and_request_required')
    if request['run_id']!=transfer['run_id']:raise ValueError('recall_run_conflict')
    if db.execute('SELECT max(id) FROM run').fetchone()[0]!=request['run_id']:
        raise ValueError('recall_decision_stale')
    # A recall reaches externally only for objects the recipient actually holds:
    # remote_erase obligation AND an immutable 'received' receipt on this transfer.
    # Objects still in local custody (pending/rejected) must never enter external proof.
    items=db.execute("""SELECT i.subject,c.expected_hash FROM erasure_item i
      JOIN custody_item c ON c.subject=i.subject AND c.transfer_id=?
      WHERE i.request_id=? AND i.obligation='remote_erase'
      AND EXISTS(SELECT 1 FROM custody_receipt r WHERE r.transfer_id=c.transfer_id
        AND r.subject=i.subject AND r.verdict='received')
      ORDER BY i.subject""",
      (transfer_id,request_id)).fetchall()
    if not items:raise ValueError('no_remote_obligation_for_transfer')
    old=db.execute('SELECT * FROM custody_recall WHERE id=?',(recall_id,)).fetchone()
    if old:
        if old['request_id']!=request_id or old['transfer_id']!=transfer_id:
            raise ValueError('recall_identity_conflict')
        db.close();return describe(db_path,recall_id)
    with db:
        db.execute('INSERT INTO custody_recall VALUES (?,?,?,?,?,?)',
                   (recall_id,request_id,transfer_id,transfer['recipient'],request['run_id'],'pending'))
        db.executemany('INSERT INTO recall_item VALUES (?,?,?,?,?)',
                       ((recall_id,x['subject'],x['expected_hash'],'pending',None) for x in items))
    db.close();return describe(db_path,recall_id)

def submit(db_path,recall_id,recipient,receipts):
    """Persist every attempt; good and bad receipts in a batch get separate verdicts."""
    if not isinstance(receipts,list) or not receipts:raise ValueError('receipts_required')
    db=connect(db_path);db.executescript(SCHEMA)
    db.execute('BEGIN IMMEDIATE')
    try:
        case=db.execute('SELECT * FROM custody_recall WHERE id=?',(recall_id,)).fetchone()
        if not case:raise ValueError('unknown_recall')
        if recipient!=case['recipient']:raise ValueError('recall_recipient_mismatch')
        if db.execute('SELECT max(id) FROM run').fetchone()[0]!=case['run_id']:
            raise ValueError('recall_decision_stale')
        config=json.loads(db.execute("SELECT b.config_raw FROM erasure_request r JOIN batch b ON b.id=r.batch_id WHERE r.id=?",(case['request_id'],)).fetchone()[0])
        secret=config.get('custody_keys',{}).get(recipient)
        if not secret:raise ValueError('recipient_key_required')
        for receipt in receipts:
            if not all(receipt.get(k) for k in ('event_key','subject','sha256','certificate')):
                raise ValueError('incomplete_receipt')
            item=db.execute('SELECT * FROM recall_item WHERE recall_id=? AND subject=?',
                            (recall_id,receipt['subject'])).fetchone()
            if not item:raise ValueError('receipt_outside_recall')
            digest=_digest(receipt)
            old=db.execute('SELECT * FROM recall_attempt WHERE event_key=?',(receipt['event_key'],)).fetchone()
            if old:
                if old['recall_id']!=recall_id or old['receipt_hash']!=digest:
                    raise ValueError('receipt_identity_conflict')
                continue
            duplicate=db.execute("SELECT 1 FROM recall_item WHERE certificate=? AND NOT (recall_id=? AND subject=?)",
                                 (receipt['certificate'],recall_id,receipt['subject'])).fetchone()
            signed=f"{recall_id}|{receipt['subject']}|{receipt['sha256']}|{receipt['event_key']}".encode()
            signature=hmac.new(secret.encode(),signed,hashlib.sha256).hexdigest()
            authentic=hmac.compare_digest(signature,receipt['certificate'])
            valid=receipt['sha256']==item['expected_hash'] and authentic and not duplicate
            verdict='confirmed' if valid else 'disputed'
            reason='matched_handoff_hash_and_signature' if valid else ('certificate_reused' if duplicate else ('hash_mismatch' if receipt['sha256']!=item['expected_hash'] else 'signature_invalid'))
            db.execute('INSERT INTO recall_attempt VALUES (?,?,?,?,?,?)',
                       (receipt['event_key'],recall_id,receipt['subject'],digest,verdict,reason))
            if valid:
                if item['state']=='confirmed' and item['certificate']!=receipt['certificate']:
                    raise ValueError('confirmed_receipt_conflict')
                db.execute("UPDATE recall_item SET state='confirmed',certificate=? WHERE recall_id=? AND subject=?",
                           (receipt['certificate'],recall_id,receipt['subject']))
            elif item['state']!='confirmed':
                db.execute("UPDATE recall_item SET state='disputed' WHERE recall_id=? AND subject=?",
                           (recall_id,receipt['subject']))
        states=[r['state'] for r in db.execute('SELECT state FROM recall_item WHERE recall_id=?',(recall_id,))]
        state='completed' if all(x=='confirmed' for x in states) else (
            'partial' if 'confirmed' in states else ('disputed' if 'disputed' in states else 'pending'))
        db.execute('UPDATE custody_recall SET state=? WHERE id=?',(state,recall_id))
        db.commit()
    except Exception:
        db.rollback();raise
    finally:db.close()
    return describe(db_path,recall_id)

def describe(db_path,recall_id):
    db=connect(db_path);db.executescript(SCHEMA)
    row=db.execute('SELECT * FROM custody_recall WHERE id=?',(recall_id,)).fetchone()
    if not row:raise ValueError('unknown_recall')
    result={'recall':recall_id,'request':row['request_id'],'transfer':row['transfer_id'],
            'state':row['state'],'items':[dict(x) for x in db.execute(
                'SELECT * FROM recall_item WHERE recall_id=? ORDER BY subject',(recall_id,))],
            'attempts':[dict(x) for x in db.execute(
                'SELECT event_key,subject,verdict,reason FROM recall_attempt WHERE recall_id=? ORDER BY event_key',(recall_id,))]}
    db.close();return result
