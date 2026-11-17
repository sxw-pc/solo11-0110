"""Recoverable, multi-object execution of an authorized local destruction plan.

The plan body (frozen by ``rules.action('plan', ...)``) is the authority.  An
execution *attempt* freezes that authority together with the sandbox and the
recovery policy before anything is touched.  Files are never unlinked while
they are still at their delivery path: each object is moved into a
per-attempt quarantine directory that normal delivery does not read, one
object at a time, and every transition is journalled.

The filesystem and SQLite cannot share a transaction, so the invariant is:

* every ``execution_object``/``execution_event`` row describes a state that can
  be re-checked against the bytes on disk (path + SHA-256);
* a destructive ``execution_proof`` row is inserted only after the quarantined
  bytes were verified and removed, in the same database transaction that
  advances the object to ``destroyed``;
* an interruption therefore leaves enough durable evidence to deterministically
  either finish (``complete_on_recovery``) or roll back
  (``restore_on_recovery``) an attempt whose objects are *all* safely
  quarantined, and to refuse both when the attempt cannot be proven whole.

Legacy ``execution`` rows written by the old single-file protocol are treated
as legacy-only: recovery never reads them, they are never converted into a
proof, and the report labels them ``protocol='legacy'``.  New attempts write a
compatibility mirror row there purely for old display consumers.
"""
import errno
import fcntl
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .store import connect

PROTOCOL = 'quarantine-v1'
ACTIVE = ('prepared', 'quarantining', 'quarantined', 'disposing', 'restoring')
FINAL = ('complete', 'restored', 'partial', 'disputed', 'stale')
POLICIES = ('complete_on_recovery', 'restore_on_recovery')
QUARANTINE_DIR = '.retaincase-quarantine'


class Interruption(RuntimeError):
    """Raised by an injected fault; simulates the process dying."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _now():
    return datetime.now(timezone.utc).isoformat()


def _sha_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def _sha_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def _json_digest(value):
    return _sha_bytes(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                 separators=(',', ':')).encode())


def _inside(root, path):
    return path != root and root in path.parents


def _begin(db):
    """Start an IMMEDIATE transaction unless sqlite3 already opened one."""
    if not db.in_transaction:
        db.execute('BEGIN IMMEDIATE')


def _fault(injector, name, **context):
    """Deterministic interruption seam.

    ``injector`` may be a callable receiving ``(point, context)`` (it may raise
    ``Interruption``) or a container of point names.  A fault is raised exactly
    at the named boundary; no further filesystem or database write happens.
    """
    if injector is None:
        return
    if callable(injector):
        injector(name, context)
    elif name in injector:
        raise Interruption(name)


# ---------------------------------------------------------------------------
# Attempt inspection helpers
# ---------------------------------------------------------------------------

def _attempt_row(db, attempt_id):
    return db.execute('SELECT * FROM execution_attempt WHERE id=?', (attempt_id,)).fetchone()


def _objects(db, attempt_id):
    return db.execute('SELECT * FROM execution_object WHERE attempt_id=? ORDER BY ordinal',
                      (attempt_id,)).fetchall()


def _append_event(db, attempt_id, kind, subject, detail):
    seq = db.execute('SELECT COALESCE(max(seq),0)+1 FROM execution_event WHERE attempt_id=?',
                     (attempt_id,)).fetchone()[0]
    db.execute('INSERT INTO execution_event(attempt_id,seq,kind,subject,detail) '
               'VALUES (?,?,?,?,?)',
               (attempt_id, seq, kind, subject,
                json.dumps(detail, sort_keys=True, ensure_ascii=False)))
    return seq


def _set_state(db, attempt_id, state, detail=None):
    if detail is None:
        db.execute('UPDATE execution_attempt SET state=?,updated_at=? WHERE id=?',
                   (state, _now(), attempt_id))
    else:
        db.execute('UPDATE execution_attempt SET state=?,detail=?,updated_at=? WHERE id=?',
                   (state, json.dumps(detail, sort_keys=True, ensure_ascii=False),
                    _now(), attempt_id))


def _set_object(db, attempt_id, subject, state, observed_hash=None, reason=None):
    fields = ['state=?', 'updated_at=?']
    args = [state, _now()]
    if observed_hash is not None:
        fields.append('observed_hash=?')
        args.append(observed_hash)
    if reason is not None:
        fields.append('reason=?')
        args.append(reason)
    args.extend([attempt_id, subject])
    db.execute(f"UPDATE execution_object SET {','.join(fields)} "
               "WHERE attempt_id=? AND subject=?", tuple(args))


def _quarantine_root(sandbox, attempt_id):
    return sandbox / QUARANTINE_DIR / attempt_id


def _release_claims(db, attempt_id):
    db.execute('DELETE FROM execution_claim WHERE attempt_id=?', (attempt_id,))


def _commit(db):
    db.commit()


def _rollback(db):
    db.rollback()


def _commit_dispute(db, attempt_id, subject, reason, observed_hash=None):
    """Enter a terminal dispute without touching the conflicting bytes."""
    try:
        _begin(db)
        _set_object(db, attempt_id, subject, 'disputed',
                    observed_hash=observed_hash, reason=reason)
        _set_state(db, attempt_id, 'disputed', {'subject': subject, 'reason': reason})
        _append_event(db, attempt_id, 'dispute', subject, {'reason': reason})
        _release_claims(db, attempt_id)
        _commit(db)
    except Exception:
        _rollback(db)
        raise
    return describe_db(db, attempt_id)


def _prune_empty_dirs(directory, sandbox):
    """Remove empty quarantine subdirectories, never the sandbox itself."""
    directory = Path(directory).resolve()
    stop = (sandbox / QUARANTINE_DIR).resolve()
    while _inside(stop, directory):
        try:
            directory.rmdir()
        except OSError:
            break
        directory = directory.parent


# ---------------------------------------------------------------------------
# Freezing authority
# ---------------------------------------------------------------------------

def _config_and_batch(db):
    row = db.execute('SELECT config_raw,config_hash FROM batch LIMIT 1').fetchone()
    if not row:
        raise ValueError('not_initialized')
    if _sha_bytes(row['config_raw']) != row['config_hash']:
        raise ValueError('batch_config_tampered')
    return json.loads(row['config_raw'])


def _latest_run(db):
    return db.execute('SELECT max(id) FROM run').fetchone()[0]


def _read_plan(plan_path):
    """Read the plan file; keep the historical ``plan.json`` default."""
    path = Path(plan_path or 'plan.json')
    body = path.read_text(encoding='utf-8')
    return body, _sha_bytes(body.encode('utf-8'))


def _authorize(db, body, plan_digest):
    """Full check required before a *new* attempt may start."""
    latest = _latest_run(db)
    if not db.execute('SELECT 1 FROM plan WHERE digest=? AND run_id=? AND body=?',
                      (plan_digest, latest, body)).fetchone():
        raise ValueError('plan_not_authorized_for_latest_run')
    plan = json.loads(body)
    eligible = {r['subject'] for r in db.execute(
        "SELECT subject FROM decision WHERE run_id=? AND status='可销毁'", (latest,))}
    if {item.get('subject') for item in plan} != eligible or len(plan) != len(eligible):
        raise ValueError('plan_decision_mismatch')
    return latest


def _manifest(sandbox, config, plan):
    subjects = set()
    targets = []
    manifest = []
    for ordinal, item in enumerate(plan):
        subject = item.get('subject')
        spec = config['subjects'].get(subject)
        if (not spec or item.get('path') != spec['path']
                or item.get('sha256') != spec.get('sha256', '')):
            raise ValueError('plan_config_mismatch')
        if not item.get('sha256'):
            raise ValueError('object_hash_required')
        if subject in subjects:
            raise ValueError('duplicate_plan_subject')
        relative = Path(item['path'])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('unsafe_plan')
        if relative.parts and relative.parts[0] == QUARANTINE_DIR:
            raise ValueError('unsafe_plan')
        target = (sandbox / relative).resolve()
        if not _inside(sandbox, target):
            raise ValueError('unsafe_path')
        subjects.add(subject)
        targets.append(str(target))
        manifest.append({'ordinal': ordinal, 'subject': subject, 'path': item['path'],
                         'sha256': item['sha256']})
    if len(set(targets)) != len(targets):
        raise ValueError('unsafe_plan')
    return manifest


def _manifest_digest(sandbox, policy, plan_digest, run_id, manifest):
    return _json_digest({'protocol': PROTOCOL, 'sandbox': str(sandbox), 'policy': policy,
                         'plan_digest': plan_digest, 'run_id': run_id,
                         'objects': manifest})


def _attempt_id(sandbox, policy, plan_digest, run_id, manifest):
    # Deterministic: re-running the same frozen authority maps to the same
    # attempt, which is what makes recovery and replay idempotent.
    return _manifest_digest(sandbox, policy, plan_digest, run_id, manifest)[:32]


# ---------------------------------------------------------------------------
# Sandbox lock
# ---------------------------------------------------------------------------

class _SandboxLock:
    """Process-level advisory lock; serializes execution in one sandbox.

    A second concurrent writer receives ``sandbox_execution_busy`` rather than
    racing the first one; this is the deterministic conflict decision for two
    attempts in the same sandbox.
    """

    def __init__(self, sandbox):
        self.path = sandbox / QUARANTINE_DIR / '.lock'
        self.handle = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # The quarantine area must never be readable by ordinary delivery
        # consumers, even though it is already excluded from the plan.
        try:
            self.path.parent.chmod(0o700)
        except OSError:
            pass
        self.handle = open(self.path, 'a+')
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.handle.close()
            self.handle = None
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                raise ValueError('sandbox_execution_busy')
            raise
        return self

    def __exit__(self, *exc_info):
        if self.handle is not None:
            try:
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            finally:
                self.handle.close()
        return False


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def execute(db_path, plan_path, sandbox, recovery_policy='complete_on_recovery',
            injector=None, nonce=''):
    """Validate everything first, then quarantine all targets, then dispose.

    ``recovery_policy`` is frozen into the attempt on first execution.  Calling
    again for the same frozen authority is an idempotent replay/recovery; a
    different policy for an already-attempted plan is rejected.  ``nonce`` is
    an explicit operator decision to start a fresh attempt after one already
    reached a final state (it never adopts an old attempt's quarantine files).
    """
    if recovery_policy not in POLICIES:
        raise ValueError('invalid_recovery_policy')
    sandbox = Path(sandbox).resolve()
    sandbox.mkdir(parents=True, exist_ok=True)
    with _SandboxLock(sandbox):
        db = connect(db_path)
        try:
            return _execute_locked(db, plan_path, sandbox, recovery_policy,
                                   injector, nonce)
        finally:
            db.close()


def _execute_locked(db, plan_path, sandbox, policy, injector, nonce=''):
    config = _config_and_batch(db)
    body, plan_digest = _read_plan(plan_path)

    # An attempt already frozen for this plan is resumed under its frozen
    # manifest/policy -- even if a newer decision exists.  A new decision can
    # never adopt or extend the old attempt.
    prior = db.execute('SELECT * FROM execution_attempt WHERE sandbox=? AND plan_digest=? '
                       'ORDER BY created_at,id', (str(sandbox), plan_digest)).fetchall()
    if prior and not nonce:
        if any(row['recovery_policy'] != policy for row in prior):
            raise ValueError('attempt_policy_conflict')
        attempt = prior[0]
        manifest = json.loads(attempt['manifest'])
        if (not db.execute('SELECT 1 FROM plan WHERE digest=? AND body=?',
                           (plan_digest, body)).fetchone()
                or _manifest_digest(sandbox, attempt['recovery_policy'], plan_digest,
                                    attempt['run_id'], manifest) != attempt['manifest_digest']):
            raise ValueError('attempt_identity_conflict')
        return _recover_locked(db, attempt['id'], injector=injector)

    run_id = _authorize(db, body, plan_digest)
    manifest = _manifest(sandbox, config, json.loads(body))
    attempt_id = _attempt_id(sandbox, policy, plan_digest, run_id, manifest)
    if nonce:
        attempt_id = hashlib.sha256(f'{attempt_id}:{nonce}'.encode()).hexdigest()[:32]
    existing = _attempt_row(db, attempt_id)
    if existing:
        if existing['recovery_policy'] != policy:
            raise ValueError('attempt_policy_conflict')
        return _recover_locked(db, attempt_id, injector=injector)
    mdigest = _manifest_digest(sandbox, policy, plan_digest, run_id, manifest)
    _assert_no_claim_conflict(db, sandbox, manifest)
    return _start_attempt(db, sandbox, policy, plan_digest, run_id, manifest,
                          mdigest, attempt_id, injector)


def _assert_no_claim_conflict(db, sandbox, manifest):
    for item in manifest:
        target = str((sandbox / item['path']).resolve())
        claim = db.execute('SELECT attempt_id FROM execution_claim '
                           'WHERE sandbox=? AND original_path=?',
                           (str(sandbox), target)).fetchone()
        if claim:
            raise ValueError(f'object_claimed_by_other_attempt:{item["subject"]}')


def _verify_targets(sandbox, manifest):
    """Pre-flight: every target must exist with the frozen bytes."""
    verified = {}
    for item in manifest:
        target = (sandbox / item['path']).resolve()
        if not _inside(sandbox, target):
            raise ValueError('unsafe_path')
        if not target.is_file():
            raise ValueError(f'target_missing:{item["subject"]}')
        observed = _sha_file(target)
        if observed != item['sha256']:
            raise ValueError(f'hash_changed:{item["subject"]}')
        verified[item['subject']] = observed
    return verified


def _start_attempt(db, sandbox, policy, plan_digest, run_id, manifest, mdigest,
                   attempt_id, injector):
    # Nothing is written or moved until *every* target is verified.
    verified = _verify_targets(sandbox, manifest)
    _fault(injector, 'before_commit', attempt_id=attempt_id)
    try:
        _begin(db)
        if _attempt_row(db, attempt_id):
            _rollback(db)
            return _recover_locked(db, attempt_id, injector=injector)
        _assert_no_claim_conflict(db, sandbox, manifest)
        db.execute('INSERT INTO execution_attempt('
                   'id,plan_digest,run_id,sandbox,recovery_policy,state,manifest,'
                   'manifest_digest) VALUES (?,?,?,?,?,?,?,?)',
                   (attempt_id, plan_digest, run_id, str(sandbox), policy, 'prepared',
                    json.dumps(manifest, sort_keys=True, ensure_ascii=False), mdigest))
        for item in manifest:
            target = (sandbox / item['path']).resolve()
            qpath = (_quarantine_root(sandbox, attempt_id) / item['path']).resolve()
            if not _inside(sandbox, qpath):
                raise ValueError('unsafe_path')
            db.execute('INSERT INTO execution_object('
                       'attempt_id,ordinal,subject,original_path,expected_hash,'
                       'quarantine_path,state) VALUES (?,?,?,?,?,?,?)',
                       (attempt_id, item['ordinal'], item['subject'],
                        str(Path(item['path'])), item['sha256'],
                        str(qpath.relative_to(sandbox)), 'pending'))
            db.execute('INSERT INTO execution_claim(sandbox,original_path,attempt_id) '
                       'VALUES (?,?,?)', (str(sandbox), str(target), attempt_id))
        _append_event(db, attempt_id, 'prepared', None,
                      {'policy': policy, 'plan_digest': plan_digest, 'run_id': run_id,
                       'subjects': [x['subject'] for x in manifest],
                       'protocol': PROTOCOL, 'verified_hashes': verified})
        _set_state(db, attempt_id, 'quarantining')
        _commit(db)
    except Exception:
        _rollback(db)
        raise
    _fault(injector, 'after_commit', attempt_id=attempt_id)
    return _quarantine_all(db, attempt_id, sandbox, injector, skip_done=True)


# ---------------------------------------------------------------------------
# Quarantine
# ---------------------------------------------------------------------------

def _quarantine_all(db, attempt_id, sandbox, injector, skip_done=True):
    for obj in _objects(db, attempt_id):
        if obj['state'] == 'disputed':
            return describe_db(db, attempt_id)
        if obj['state'] == 'quarantined' and skip_done:
            continue
        if obj['state'] in ('destroyed', 'destroying', 'restored'):
            continue
        source = (sandbox / obj['original_path']).resolve()
        qpath = (sandbox / obj['quarantine_path']).resolve()
        if not _inside(sandbox, source) or not _inside(sandbox, qpath):
            return _commit_dispute(db, attempt_id, obj['subject'], 'unsafe_path')
        if qpath.exists():
            # Moved by an interrupted earlier step; verify before adopting it.
            if not qpath.is_file():
                return _commit_dispute(db, attempt_id, obj['subject'],
                                       'quarantine_conflict')
            observed = _sha_file(qpath)
            if observed != obj['expected_hash']:
                return _commit_dispute(db, attempt_id, obj['subject'],
                                       'quarantine_hash_mismatch', observed)
            if source.exists():
                return _commit_dispute(db, attempt_id, obj['subject'],
                                       'original_path_occupied')
            _finish_quarantine_row(db, attempt_id, obj['subject'], observed)
            _fault(injector, 'after_quarantine', attempt_id=attempt_id,
                   subject=obj['subject'])
            continue
        if not source.is_file():
            return _commit_dispute(db, attempt_id, obj['subject'], 'target_missing')
        observed = _sha_file(source)
        if observed != obj['expected_hash']:
            return _commit_dispute(db, attempt_id, obj['subject'],
                                   'hash_changed', observed)
        # Journal the intent with the verified hash *before* the move, so an
        # interruption between rename and its row is fully replayable.
        try:
            _begin(db)
            _set_object(db, attempt_id, obj['subject'], 'moving',
                        observed_hash=observed)
            _append_event(db, attempt_id, 'quarantine_intent', obj['subject'],
                          {'hash': observed})
            _commit(db)
        except Exception:
            _rollback(db)
            raise
        try:
            qpath.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, qpath)
        except OSError as exc:
            return _commit_dispute(db, attempt_id, obj['subject'],
                                   f'quarantine_failed:{exc.errno}')
        _fault(injector, 'quarantine_before_commit', attempt_id=attempt_id,
               subject=obj['subject'])
        moved = _sha_file(qpath)
        if moved != obj['expected_hash']:
            return _commit_dispute(db, attempt_id, obj['subject'],
                                   'quarantine_hash_mismatch', moved)
        _finish_quarantine_row(db, attempt_id, obj['subject'], moved)
        _fault(injector, 'after_quarantine', attempt_id=attempt_id,
               subject=obj['subject'])
    try:
        _begin(db)
        _append_event(db, attempt_id, 'quarantined', None,
                      {'subjects': [o['subject'] for o in _objects(db, attempt_id)]})
        _set_state(db, attempt_id, 'quarantined')
        _commit(db)
    except Exception:
        _rollback(db)
        raise
    _fault(injector, 'after_ledger_commit', attempt_id=attempt_id, phase='quarantined')
    return _finalize(db, attempt_id, sandbox, injector)


def _finish_quarantine_row(db, attempt_id, subject, observed):
    try:
        _begin(db)
        _set_object(db, attempt_id, subject, 'quarantined', observed_hash=observed)
        _append_event(db, attempt_id, 'quarantined_one', subject,
                      {'observed_hash': observed})
        _commit(db)
    except Exception:
        _rollback(db)
        raise


# ---------------------------------------------------------------------------
# Consistency checks used before and during recovery
# ---------------------------------------------------------------------------

def _quarantine_integrity(db, attempt_id, sandbox, policy):
    """All objects must be fully isolated with verifiable bytes.

    Only then may final disposition run: ``destroy`` under
    ``complete_on_recovery`` or ``restore`` under ``restore_on_recovery``.  A
    partially isolated attempt never satisfies this predicate.
    """
    problems = []
    for obj in _objects(db, attempt_id):
        state = obj['state']
        if state == 'disputed':
            problems.append((obj['subject'], 'object_disputed'))
            continue
        if state == 'destroyed':
            if policy != 'complete_on_recovery':
                problems.append((obj['subject'], 'irreversible_destruction'))
            continue
        if state == 'destroying':
            if policy != 'complete_on_recovery':
                problems.append((obj['subject'], 'irreversible_disposition_started'))
            continue
        if state == 'restored':
            if policy != 'restore_on_recovery':
                problems.append((obj['subject'], 'restored_under_complete_policy'))
            continue
        if state not in ('quarantined', 'moving'):
            problems.append((obj['subject'], 'not_quarantined'))
            continue
        if state == 'moving':
            # Intent committed, move possibly in flight or completed.  Verify
            # bytes at whichever home they occupy before treating it as done.
            qpath = (sandbox / obj['quarantine_path']).resolve()
            source = (sandbox / obj['original_path']).resolve()
            if obj['observed_hash'] != obj['expected_hash']:
                problems.append((obj['subject'], 'move_intent_unverified'))
                continue
            if (not _inside(sandbox, qpath) or not _inside(sandbox, source)
                    or source.exists() or not qpath.is_file()
                    or _sha_file(qpath) != obj['expected_hash']):
                problems.append((obj['subject'], 'not_quarantined'))
            continue
        qpath = (sandbox / obj['quarantine_path']).resolve()
        source = (sandbox / obj['original_path']).resolve()
        if not _inside(sandbox, qpath) or not _inside(sandbox, source):
            problems.append((obj['subject'], 'unsafe_path'))
            continue
        if source.exists():
            # Interrupted restore: move done, ledger row not yet committed.
            if (policy == 'restore_on_recovery' and not qpath.exists()
                    and source.is_file()
                    and _sha_file(source) == obj['expected_hash']):
                continue
            problems.append((obj['subject'], 'original_path_occupied'))
            continue
        if qpath.is_file():
            if _sha_file(qpath) != obj['expected_hash']:
                problems.append((obj['subject'], 'quarantine_hash_mismatch'))
        else:
            problems.append((obj['subject'], 'quarantine_missing'))
    return problems


# ---------------------------------------------------------------------------
# Final disposition
# ---------------------------------------------------------------------------

def _finalize(db, attempt_id, sandbox, injector):
    row = _attempt_row(db, attempt_id)
    problems = _quarantine_integrity(db, attempt_id, sandbox, row['recovery_policy'])
    if problems:
        subject, reason = problems[0]
        return _commit_dispute(db, attempt_id, subject, reason)
    if row['recovery_policy'] == 'restore_on_recovery':
        return _restore_all(db, attempt_id, sandbox, injector)
    return _destroy_all(db, attempt_id, sandbox, injector)


def _destroy_all(db, attempt_id, sandbox, injector):
    row = _attempt_row(db, attempt_id)
    run_id = row['run_id']
    plan_digest = row['plan_digest']
    try:
        _begin(db)
        if row['state'] != 'disposing':
            _append_event(db, attempt_id, 'disposing', None, {})
            _set_state(db, attempt_id, 'disposing')
        _commit(db)
    except Exception:
        _rollback(db)
        raise
    _fault(injector, 'during_disposition', attempt_id=attempt_id, phase='start')
    newly = []
    for obj in _objects(db, attempt_id):
        if obj['state'] == 'destroyed':
            continue
        if obj['state'] == 'disputed':
            return describe_db(db, attempt_id)
        qpath = (sandbox / obj['quarantine_path']).resolve()
        source = (sandbox / obj['original_path']).resolve()
        if source.exists():
            return _commit_dispute(db, attempt_id, obj['subject'],
                                   'original_path_occupied')
        if qpath.is_file():
            observed = _sha_file(qpath)
            if observed != obj['expected_hash']:
                return _commit_dispute(db, attempt_id, obj['subject'],
                                       'quarantine_hash_mismatch', observed)
        elif obj['state'] == 'destroying':
            # Crash after unlink, before the proof commit: the journal recorded
            # the verified hash immediately before the unlink.
            observed = obj['observed_hash']
            if observed != obj['expected_hash']:
                return _commit_dispute(db, attempt_id, obj['subject'],
                                       'destroy_intent_unverified')
        else:
            return _commit_dispute(db, attempt_id, obj['subject'],
                                   'quarantine_missing')
        try:
            _begin(db)
            _set_object(db, attempt_id, obj['subject'], 'destroying',
                        observed_hash=observed)
            _append_event(db, attempt_id, 'destroying', obj['subject'],
                          {'hash': observed})
            _commit(db)
        except Exception:
            _rollback(db)
            raise
        _fault(injector, 'during_disposition', attempt_id=attempt_id,
               phase='before_unlink', subject=obj['subject'])
        if qpath.is_file():
            try:
                qpath.unlink()
            except OSError:
                return _commit_dispute(db, attempt_id, obj['subject'],
                                       'destroy_failed')
            _prune_empty_dirs(qpath.parent, sandbox)
        _fault(injector, 'during_disposition', attempt_id=attempt_id,
               phase='after_unlink', subject=obj['subject'])
        try:
            _begin(db)
            db.execute('INSERT OR IGNORE INTO execution_proof('
                       'attempt_id,run_id,subject,plan_digest,before_hash,after_state) '
                       'VALUES (?,?,?,?,?,?)',
                       (attempt_id, run_id, obj['subject'], plan_digest,
                        obj['expected_hash'], 'absent'))
            _set_object(db, attempt_id, obj['subject'], 'destroyed',
                        observed_hash=obj['expected_hash'])
            _append_event(db, attempt_id, 'destroyed', obj['subject'],
                          {'proof': True, 'before_hash': obj['expected_hash']})
            # Compatibility mirror for the legacy display protocol.  It is
            # never read as recoverable or fulfilment evidence.
            db.execute('INSERT OR IGNORE INTO execution('
                       'run_id,subject,action,before_hash,after_state) '
                       'VALUES (?,?,?,?,?)',
                       (run_id, obj['subject'], 'destroy', obj['expected_hash'],
                        'absent'))
            _commit(db)
        except Exception:
            _rollback(db)
            raise
        newly.append(obj['subject'])
        _fault(injector, 'during_disposition', attempt_id=attempt_id,
               phase='after_proof', subject=obj['subject'])
    try:
        _begin(db)
        _append_event(db, attempt_id, 'complete', None,
                      {'subjects': [o['subject'] for o in _objects(db, attempt_id)]})
        _set_state(db, attempt_id, 'complete')
        _release_claims(db, attempt_id)
        _commit(db)
    except Exception:
        _rollback(db)
        raise
    _fault(injector, 'after_ledger_commit', attempt_id=attempt_id, phase='complete')
    result = describe_db(db, attempt_id)
    result['newly_destroyed'] = newly
    return result


def _restore_all(db, attempt_id, sandbox, injector):
    try:
        _begin(db)
        if _attempt_row(db, attempt_id)['state'] != 'restoring':
            _append_event(db, attempt_id, 'restoring', None, {})
            _set_state(db, attempt_id, 'restoring')
        _commit(db)
    except Exception:
        _rollback(db)
        raise
    for obj in _objects(db, attempt_id):
        if obj['state'] == 'restored':
            continue
        if obj['state'] in ('destroyed', 'destroying'):
            return _commit_dispute(db, attempt_id, obj['subject'],
                                   'partial_destruction_irreversible')
        qpath = (sandbox / obj['quarantine_path']).resolve()
        source = (sandbox / obj['original_path']).resolve()
        if not _inside(sandbox, qpath) or not _inside(sandbox, source):
            return _commit_dispute(db, attempt_id, obj['subject'], 'unsafe_path')
        if not qpath.is_file():
            # Interrupted restore: the move completed, the ledger row did not.
            if source.is_file() and _sha_file(source) == obj['expected_hash']:
                _finish_restore_row(db, attempt_id, obj['subject'],
                                    obj['expected_hash'])
                _fault(injector, 'after_restore', attempt_id=attempt_id,
                       subject=obj['subject'])
                continue
            return _commit_dispute(db, attempt_id, obj['subject'],
                                   'quarantine_missing')
        observed = _sha_file(qpath)
        if observed != obj['expected_hash']:
            return _commit_dispute(db, attempt_id, obj['subject'],
                                   'quarantine_hash_mismatch', observed)
        if source.exists():
            # Never overwrite a file that appeared at the original location.
            return _commit_dispute(db, attempt_id, obj['subject'],
                                   'restore_path_occupied')
        try:
            source.parent.mkdir(parents=True, exist_ok=True)
            os.replace(qpath, source)
        except OSError:
            return _commit_dispute(db, attempt_id, obj['subject'], 'restore_failed')
        _fault(injector, 'restore_before_commit', attempt_id=attempt_id,
               subject=obj['subject'])
        back = _sha_file(source)
        if back != obj['expected_hash']:
            return _commit_dispute(db, attempt_id, obj['subject'],
                                   'restore_hash_mismatch', back)
        _prune_empty_dirs(qpath.parent, sandbox)
        _finish_restore_row(db, attempt_id, obj['subject'], back)
        _fault(injector, 'after_restore', attempt_id=attempt_id, subject=obj['subject'])
    try:
        _begin(db)
        _append_event(db, attempt_id, 'restored_all', None,
                      {'subjects': [o['subject'] for o in _objects(db, attempt_id)],
                       'fulfilled': False})
        _set_state(db, attempt_id, 'restored',
                   {'fulfilled': False, 'reason': 'restore_on_recovery'})
        _release_claims(db, attempt_id)
        _commit(db)
    except Exception:
        _rollback(db)
        raise
    _fault(injector, 'after_ledger_commit', attempt_id=attempt_id, phase='restored')
    return describe_db(db, attempt_id)


def _finish_restore_row(db, attempt_id, subject, observed):
    try:
        _begin(db)
        _set_object(db, attempt_id, subject, 'restored', observed_hash=observed)
        _append_event(db, attempt_id, 'restored_one', subject,
                      {'observed_hash': observed})
        _commit(db)
    except Exception:
        _rollback(db)
        raise


def _restore_partial(db, attempt_id, sandbox, injector):
    """Roll back a partially isolated attempt; it can never count as fulfilled.

    Objects already quarantined are restored after a hash check; objects never
    moved are verified in place and left alone.  The attempt is marked
    ``partial`` (a final, unfulfilled state).  This is the only outcome either
    recovery policy may produce when the attempt is not fully isolated: a
    partially isolated plan can never claim whole-plan completion.
    """
    for obj in _objects(db, attempt_id):
        state = obj['state']
        if state == 'disputed':
            return describe_db(db, attempt_id)
        if state in ('destroyed', 'destroying', 'restored'):
            # Destruction cannot follow partial isolation in a well-formed
            # attempt; if it did, refuse rather than pretend a rollback.
            return _commit_dispute(db, attempt_id, obj['subject'],
                                   'partial_destruction_irreversible')
        qpath = (sandbox / obj['quarantine_path']).resolve()
        source = (sandbox / obj['original_path']).resolve()
        if not _inside(sandbox, qpath) or not _inside(sandbox, source):
            return _commit_dispute(db, attempt_id, obj['subject'], 'unsafe_path')
        source_ok = source.is_file() and _sha_file(source) == obj['expected_hash']
        qpath_ok = qpath.is_file() and _sha_file(qpath) == obj['expected_hash']
        if state in ('pending', 'moving'):
            if qpath_ok and not source.exists():
                # Crash window: the move happened, its row was never committed.
                pass
            elif source_ok and not qpath.exists():
                # Never moved: verified in place and left untouched.
                continue
            elif source_ok and qpath.exists():
                return _commit_dispute(db, attempt_id, obj['subject'],
                                       'pending_bytes_duplicated')
            else:
                return _commit_dispute(db, attempt_id, obj['subject'],
                                       'pending_bytes_invalid')
        else:  # quarantined
            if qpath_ok and not source.exists():
                pass
            elif source_ok and not qpath.exists():
                # Never moved or already restored: leave the bytes in place.
                _finish_restore_row(db, attempt_id, obj['subject'],
                                    obj['expected_hash'])
                continue
            elif qpath.exists():
                return _commit_dispute(db, attempt_id, obj['subject'],
                                       'quarantine_hash_mismatch')
            else:
                return _commit_dispute(db, attempt_id, obj['subject'],
                                       'quarantine_missing')
        if source.exists():
            return _commit_dispute(db, attempt_id, obj['subject'],
                                   'restore_path_occupied')
        try:
            source.parent.mkdir(parents=True, exist_ok=True)
            os.replace(qpath, source)
        except OSError:
            return _commit_dispute(db, attempt_id, obj['subject'], 'restore_failed')
        _fault(injector, 'restore_before_commit', attempt_id=attempt_id,
               subject=obj['subject'])
        back = _sha_file(source)
        if back != obj['expected_hash']:
            return _commit_dispute(db, attempt_id, obj['subject'],
                                   'restore_hash_mismatch', back)
        _prune_empty_dirs(qpath.parent, sandbox)
        _finish_restore_row(db, attempt_id, obj['subject'], back)
        _fault(injector, 'after_restore', attempt_id=attempt_id, subject=obj['subject'])
    try:
        _begin(db)
        _append_event(db, attempt_id, 'partial_restored', None,
                      {'fulfilled': False, 'reason': 'partial_isolation_rolled_back'})
        _set_state(db, attempt_id, 'partial',
                   {'fulfilled': False, 'reason': 'partial_isolation_rolled_back'})
        _release_claims(db, attempt_id)
        _commit(db)
    except Exception:
        _rollback(db)
        raise
    _fault(injector, 'after_ledger_commit', attempt_id=attempt_id, phase='partial')
    return describe_db(db, attempt_id)


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------

def recover(db_path, attempt_id=None, sandbox=None, injector=None):
    """Idempotently resume an interrupted attempt under its frozen policy.

    With no ``attempt_id``, the latest non-final attempt in ``sandbox`` is
    resumed.  There is no way to change the frozen policy here.
    """
    db = connect(db_path)
    try:
        if attempt_id is None:
            if sandbox is None:
                raise ValueError('sandbox_or_attempt_required')
            sandbox = Path(sandbox).resolve()
            rows = db.execute('SELECT id FROM execution_attempt WHERE sandbox=? AND state IN '
                              "('prepared','quarantining','quarantined','disposing','restoring') "
                              'ORDER BY created_at,id', (str(sandbox),)).fetchall()
            if not rows:
                return {'attempt': None, 'state': 'none', 'newly_destroyed': []}
            attempt_id = rows[-1]['id']
        row = _attempt_row(db, attempt_id)
        if not row:
            raise ValueError('unknown_attempt')
        sandbox = Path(row['sandbox']).resolve()
        with _SandboxLock(sandbox):
            return _recover_locked(db, attempt_id, injector=injector)
    finally:
        db.close()


def _authorizing_plan_intact(db, plan_digest):
    row = db.execute('SELECT body FROM plan WHERE digest=?', (plan_digest,)).fetchone()
    return bool(row) and _sha_bytes(row['body'].encode('utf-8')) == plan_digest


def _recover_locked(db, attempt_id, injector=None):
    row = _attempt_row(db, attempt_id)
    if not row:
        raise ValueError('unknown_attempt')
    if row['state'] in FINAL:
        return describe_db(db, attempt_id)
    manifest = json.loads(row['manifest'])
    sandbox = Path(row['sandbox']).resolve()
    # A frozen attempt is only recoverable while its authorizing plan bytes are
    # still present and its manifest is intact.  A newer decision is irrelevant
    # to this attempt, but it can never adopt it either.
    if (not _authorizing_plan_intact(db, row['plan_digest'])
            or _manifest_digest(sandbox, row['recovery_policy'], row['plan_digest'],
                                row['run_id'], manifest) != row['manifest_digest']):
        try:
            _begin(db)
            _append_event(db, attempt_id, 'recovery_refused', None,
                          {'reason': 'authority_integrity_lost'})
            _set_state(db, attempt_id, 'stale',
                       {'reason': 'authority_integrity_lost'})
            _release_claims(db, attempt_id)
            _commit(db)
        except Exception:
            _rollback(db)
            raise
        return describe_db(db, attempt_id)
    _fault(injector, 'before_recovery', attempt_id=attempt_id)
    state = row['state']
    policy = row['recovery_policy']
    # A newer decision must never be able to claim this attempt's files, and
    # must also be able to stop an irreversible completion it no longer
    # authorizes (existing holds/dependencies are never relaxed).
    authorized = _completion_authorized(db, row)
    if state in ('prepared', 'quarantining'):
        if _fully_quarantined(db, attempt_id, sandbox):
            # Every object is isolated with durable evidence: the frozen policy
            # decides final disposition.
            if policy == 'complete_on_recovery' and not authorized:
                return _abandon_unauthorized(db, attempt_id, sandbox, injector)
            return _finalize(db, attempt_id, sandbox, injector)
        # Partial isolation can never be presented as a completed plan, under
        # either policy.  Put back what was isolated (hash-checked), leave the
        # untouched originals alone, and close the attempt as partial.
        return _restore_partial(db, attempt_id, sandbox, injector)
    if state in ('quarantined', 'disposing', 'restoring'):
        if policy == 'complete_on_recovery' and not authorized:
            return _abandon_unauthorized(db, attempt_id, sandbox, injector)
        problems = _quarantine_integrity(db, attempt_id, sandbox, policy)
        if problems:
            subject, reason = problems[0]
            return _commit_dispute(db, attempt_id, subject, reason)
        if policy == 'restore_on_recovery':
            return _restore_all(db, attempt_id, sandbox, injector)
        return _destroy_all(db, attempt_id, sandbox, injector)
    return describe_db(db, attempt_id)


def _completion_authorized(db, row):
    """Whether the attempt's frozen run is still the authoritative run.

    A newer evaluation supersedes a frozen attempt: it may reflect a new hold,
    dependency ruling, or a different plan.  An old attempt must never finish a
    destructive disposition on that basis, nor may a new plan claim its
    quarantine files.  So only an attempt of the latest run may complete.
    Restoring (the other recovery route) remains permitted for any run.
    """
    return _latest_run(db) == row['run_id']


def _abandon_unauthorized(db, attempt_id, sandbox, injector):
    """Refuse a destructive completion whose authority a newer run superseded."""
    objects = _objects(db, attempt_id)
    if any(o['state'] in ('destroyed', 'destroying') for o in objects):
        return _commit_dispute(db, attempt_id, next(
            o['subject'] for o in objects if o['state'] in ('destroyed', 'destroying')),
            'decision_superseded_after_destruction')
    # Everything is still recoverable: put each object back after a hash check.
    result = _restore_all(db, attempt_id, sandbox, injector)
    if result['state'] != 'restored':
        # A restore conflict (occupied path, corrupt bytes) is itself the final
        # finding; do not overwrite it with a stale marker.
        return result
    try:
        _begin(db)
        _append_event(db, attempt_id, 'recovery_refused', None,
                      {'reason': 'decision_superseded'})
        _set_state(db, attempt_id, 'stale',
                   {'fulfilled': False, 'reason': 'decision_superseded'})
        _commit(db)
    except Exception:
        _rollback(db)
        raise
    return describe_db(db, attempt_id)


def _fully_quarantined(db, attempt_id, sandbox):
    """Every object is provably isolated (or already final) with its bytes.

    States alone are not enough: the move is journalled *before* the rename, so
    a ``moving`` row may or may not have completed.  The filesystem decides.
    """
    rows = _objects(db, attempt_id)
    if not rows:
        return False
    for obj in rows:
        state = obj['state']
        if state in ('destroyed', 'restored'):
            continue
        if state not in ('quarantined', 'moving', 'destroying'):
            return False
        qpath = (sandbox / obj['quarantine_path']).resolve()
        source = (sandbox / obj['original_path']).resolve()
        if not _inside(sandbox, qpath) or not _inside(sandbox, source):
            return False
        if state == 'destroying' and not qpath.exists():
            # Already unlinked (or crash window after unlink); the hash intent
            # was committed before the unlink.
            if obj['observed_hash'] != obj['expected_hash'] or source.exists():
                return False
            continue
        if source.exists() or not qpath.is_file():
            return False
        if _sha_file(qpath) != obj['expected_hash']:
            return False
    return True


# ---------------------------------------------------------------------------
# Inspection
# ---------------------------------------------------------------------------

def describe(db_path, attempt_id):
    db = connect(db_path)
    try:
        return describe_db(db, attempt_id)
    finally:
        db.close()


def describe_db(db, attempt_id):
    row = _attempt_row(db, attempt_id)
    if not row:
        raise ValueError('unknown_attempt')
    objects = [dict(o) for o in _objects(db, attempt_id)]
    proofs = [dict(p) for p in db.execute(
        'SELECT * FROM execution_proof WHERE attempt_id=? ORDER BY subject',
        (attempt_id,))]
    events = [dict(e) for e in db.execute(
        'SELECT * FROM execution_event WHERE attempt_id=? ORDER BY seq',
        (attempt_id,))]
    return {'attempt': attempt_id, 'protocol': PROTOCOL, 'state': row['state'],
            'policy': row['recovery_policy'], 'plan_digest': row['plan_digest'],
            'run_id': row['run_id'], 'sandbox': row['sandbox'],
            'manifest_digest': row['manifest_digest'],
            'objects': objects, 'proofs': proofs, 'events': events,
            'fulfilled': row['state'] == 'complete',
            'recoverable': row['state'] in ACTIVE,
            'detail': json.loads(row['detail']) if row['detail'] else None,
            'newly_destroyed': []}


def verify(db_path, attempt_id):
    """Reconcile database evidence against the actual filesystem.

    Returns a list of integrity problems (empty means replayable).  A business
    dispute is reported through ``describe()['state']``; this function only
    checks that the recorded evidence matches what is on disk.  Legacy
    ``execution`` rows are never evidence for an attempt and are not consulted.
    """
    db = connect(db_path)
    try:
        row = _attempt_row(db, attempt_id)
        if not row:
            raise ValueError('unknown_attempt')
        sandbox = Path(row['sandbox']).resolve()
        problems = []
        manifest = json.loads(row['manifest'])
        if _manifest_digest(sandbox, row['recovery_policy'], row['plan_digest'],
                            row['run_id'], manifest) != row['manifest_digest']:
            problems.append('manifest_tampered')
        if not _authorizing_plan_intact(db, row['plan_digest']):
            problems.append('authorizing_plan_missing')
        expected_by_subject = {x['subject']: x['sha256'] for x in manifest}
        for obj in _objects(db, attempt_id):
            qpath = (sandbox / obj['quarantine_path']).resolve()
            source = (sandbox / obj['original_path']).resolve()
            proof = db.execute('SELECT * FROM execution_proof WHERE attempt_id=? '
                               'AND subject=?', (attempt_id, obj['subject'])).fetchone()
            expected = expected_by_subject.get(obj['subject'])
            if expected != obj['expected_hash']:
                problems.append(f'object_not_in_manifest:{obj["subject"]}')
            if not _inside(sandbox, qpath) or not _inside(sandbox, source):
                problems.append(f'unsafe_path:{obj["subject"]}')
                continue
            state = obj['state']
            source_ok = source.is_file() and _sha_file(source) == obj['expected_hash']
            qpath_ok = qpath.is_file() and _sha_file(qpath) == obj['expected_hash']
            if state == 'destroyed':
                if not proof or proof['before_hash'] != obj['expected_hash']:
                    problems.append(f'proof_missing:{obj["subject"]}')
                if qpath.exists():
                    problems.append(f'destroyed_bytes_in_quarantine:{obj["subject"]}')
                if source.exists():
                    problems.append(f'destroyed_bytes_at_source:{obj["subject"]}')
            elif state == 'restored':
                if not source_ok:
                    problems.append(f'restored_bytes_invalid:{obj["subject"]}')
                if qpath.exists():
                    problems.append(f'restore_quarantine_left:{obj["subject"]}')
                if proof:
                    problems.append(f'restored_object_has_proof:{obj["subject"]}')
            elif state == 'quarantined':
                if qpath_ok and not source.exists():
                    pass
                elif qpath.exists() and not qpath_ok:
                    problems.append(f'quarantine_invalid:{obj["subject"]}')
                elif not qpath.exists() and source_ok:
                    # Interrupted restore; the next transition will finalize it.
                    pass
                elif source.exists():
                    problems.append(f'original_path_present:{obj["subject"]}')
                else:
                    problems.append(f'quarantine_missing:{obj["subject"]}')
                if proof:
                    problems.append(f'proof_before_destroy:{obj["subject"]}')
            elif state == 'destroying':
                if qpath.exists() and not qpath_ok:
                    problems.append(f'destroying_bytes_invalid:{obj["subject"]}')
                if not qpath.exists() and source.exists():
                    problems.append(f'destroying_source_present:{obj["subject"]}')
                if proof:
                    problems.append(f'proof_in_destroying:{obj["subject"]}')
                if obj['observed_hash'] != obj['expected_hash']:
                    problems.append(f'destroy_intent_unverified:{obj["subject"]}')
            elif state == 'pending':
                if qpath.exists():
                    problems.append(f'pending_bytes_in_quarantine:{obj["subject"]}')
                if not source_ok:
                    problems.append(f'pending_bytes_invalid:{obj["subject"]}')
            elif state == 'moving':
                if obj['observed_hash'] != obj['expected_hash']:
                    problems.append(f'move_intent_unverified:{obj["subject"]}')
                if qpath.exists() and not qpath_ok:
                    problems.append(f'moving_bytes_invalid:{obj["subject"]}')
                if not qpath.exists() and not source_ok:
                    problems.append(f'moving_source_invalid:{obj["subject"]}')
            elif state == 'disputed':
                if proof:
                    problems.append(f'disputed_object_has_proof:{obj["subject"]}')
                if qpath.exists() and not qpath_ok:
                    problems.append(f'disputed_quarantine_invalid:{obj["subject"]}')
                if source.exists() and not source_ok and not qpath.exists():
                    problems.append(f'disputed_source_invalid:{obj["subject"]}')
            else:
                problems.append(f'unknown_object_state:{obj["subject"]}:{state}')
        if row['state'] in ACTIVE:
            claims = db.execute('SELECT count(*) FROM execution_claim WHERE attempt_id=?',
                                (attempt_id,)).fetchone()[0]
            if not claims:
                problems.append('active_attempt_without_claims')
        elif db.execute('SELECT count(*) FROM execution_claim WHERE attempt_id=?',
                        (attempt_id,)).fetchone()[0]:
            problems.append('final_attempt_left_claims')
        return problems
    finally:
        db.close()


def pending_attempts(db_path, sandbox=None):
    db = connect(db_path)
    try:
        sql = ('SELECT id,run_id,sandbox,recovery_policy,state FROM execution_attempt '
               "WHERE state IN ('prepared','quarantining','quarantined','disposing',"
               "'restoring')")
        args = ()
        if sandbox is not None:
            sql += ' AND sandbox=?'
            args = (str(Path(sandbox).resolve()),)
        return [dict(r) for r in db.execute(sql + ' ORDER BY created_at,id', args)]
    finally:
        db.close()


def blocked_subject(db_path, subject):
    """Return ``'destroyed'``/``'quarantined'``/``None`` for local state.

    Used by custody handoff so local isolation cannot be used to bypass the
    existing remote obligation machinery.
    """
    db = connect(db_path)
    try:
        rows = db.execute(
            'SELECT a.state attempt_state,o.state object_state '
            'FROM execution_attempt a JOIN execution_object o '
            'ON o.attempt_id=a.id WHERE o.subject=?', (subject,)).fetchall()
        blocked = None
        for row in rows:
            if row['attempt_state'] == 'complete' and row['object_state'] == 'destroyed':
                return 'destroyed'
            if row['object_state'] in ('pending', 'quarantined', 'destroying',
                                       'disputed'):
                blocked = 'quarantined'
        return blocked
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Evidence consumed by erasure fulfilment
# ---------------------------------------------------------------------------

def _plan_item(db, plan_digest, subject):
    """The frozen plan item, provided the stored body still hashes to its digest."""
    row = db.execute('SELECT body FROM plan WHERE digest=?', (plan_digest,)).fetchone()
    if not row or _sha_bytes(row['body'].encode('utf-8')) != plan_digest:
        return None
    try:
        for item in json.loads(row['body']):
            if item.get('subject') == subject:
                return item
    except (ValueError, TypeError):
        return None
    return None


def destruction_proofs(db_path, run_id, subject):
    """Final destruction proofs bound to this plan/object identity.

    Legacy ``execution`` rows are never returned.  A proof is durable evidence
    only once its attempt is no longer active (i.e. it reached a final state),
    its run matches, and the authorizing plan body still names the same subject
    with the same pre-destruction hash.  Proofs of a disputed attempt are still
    real per-object destructions, but they never make a request "fulfilled"
    while any other obligation is disputed or missing.
    """
    db = connect(db_path)
    try:
        rows = db.execute(
            'SELECT p.* FROM execution_proof p JOIN execution_attempt a '
            "ON a.id=p.attempt_id JOIN execution_object o "
            'ON o.attempt_id=p.attempt_id AND o.subject=p.subject '
            "WHERE a.state IN ('complete','restored','partial','disputed','stale') "
            "AND o.state='destroyed' AND p.run_id=? AND p.subject=? ORDER BY p.id",
            (run_id, subject)).fetchall()
        proofs = []
        for row in rows:
            item = _plan_item(db, row['plan_digest'], subject)
            if item and item.get('sha256') == row['before_hash']:
                proofs.append(dict(row))
        return proofs
    finally:
        db.close()


def pending_proofs(db_path, run_id, subject):
    """True when an unfinished attempt currently holds this object's bytes."""
    db = connect(db_path)
    try:
        return bool(db.execute(
            'SELECT 1 FROM execution_attempt a JOIN execution_object o '
            'ON o.attempt_id=a.id WHERE o.subject=? AND '
            "a.state IN ('prepared','quarantining','quarantined','disposing',"
            "'restoring')", (subject,)).fetchone())
    finally:
        db.close()


def subject_attempt_states(db_path, run_id, subject):
    """Distinct attempt states touching ``subject`` for ``run_id``.

    ``run_id`` is deliberately part of the identity: an attempt of another run
    can never be consumed as evidence for this request.
    """
    db = connect(db_path)
    try:
        return [r['state'] for r in db.execute(
            'SELECT DISTINCT a.state FROM execution_attempt a JOIN execution_object o '
            'ON o.attempt_id=a.id WHERE a.run_id=? AND o.subject=?',
            (run_id, subject))]
    finally:
        db.close()
