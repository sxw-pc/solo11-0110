"""Cross-failure-domain replica availability for frozen retained objects.

A replica is never trusted from a database counter: every protection verdict
re-reads each replica file from the sandbox and hashes it independently.
Replication is two-phase (reservation -> file landing -> ledger registration)
so an interrupted move or copy can be replayed without double-booking pool
capacity or marking an unwritten file as available.
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .store import connect
from .storage import SCHEMA as STORAGE_SCHEMA, _migrate

SCHEMA = """
CREATE TABLE IF NOT EXISTS protection_contract(
 subject TEXT PRIMARY KEY REFERENCES subject(id),
 guard TEXT NOT NULL CHECK(guard IN ('archive_guard','availability_guard')),
 run_id INTEGER NOT NULL REFERENCES run(id),
 source_path TEXT NOT NULL,
 source_digest TEXT NOT NULL,
 bytes INTEGER NOT NULL CHECK(bytes>0),
 contract_digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS replica_reservation(
 id TEXT PRIMARY KEY,
 subject TEXT NOT NULL REFERENCES subject(id),
 pool_id TEXT NOT NULL REFERENCES storage_pool(id),
 failure_domain TEXT NOT NULL,
 run_id INTEGER NOT NULL REFERENCES run(id),
 bytes INTEGER NOT NULL CHECK(bytes>0),
 source_digest TEXT NOT NULL,
 source_path TEXT NOT NULL,
 target_path TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('reserved','landed','rejected')),
 attempts INTEGER NOT NULL DEFAULT 1,
 digest TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(subject,pool_id,target_path));
CREATE TABLE IF NOT EXISTS replica(
 id INTEGER PRIMARY KEY,
 subject TEXT NOT NULL REFERENCES subject(id),
 pool_id TEXT NOT NULL REFERENCES storage_pool(id),
 failure_domain TEXT NOT NULL,
 run_id INTEGER NOT NULL REFERENCES run(id),
 reservation_id TEXT NOT NULL REFERENCES replica_reservation(id),
 file_path TEXT NOT NULL UNIQUE,
 bytes INTEGER NOT NULL CHECK(bytes>0),
 source_digest TEXT NOT NULL,
 verified_digest TEXT NOT NULL,
 verified_at TEXT NOT NULL,
 UNIQUE(subject,pool_id,file_path));
CREATE TABLE IF NOT EXISTS replica_verification(
 id INTEGER PRIMARY KEY,
 replica_id INTEGER NOT NULL REFERENCES replica(id),
 run_id INTEGER NOT NULL REFERENCES run(id),
 readable INTEGER NOT NULL,
 digest TEXT,
 bytes INTEGER,
 at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS warm_retirement(
 subject TEXT PRIMARY KEY REFERENCES subject(id),
 run_id INTEGER NOT NULL REFERENCES run(id),
 guard TEXT NOT NULL,
 source_digest TEXT NOT NULL,
 decision_json TEXT NOT NULL,
 at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
"""

GUARDS = ('archive_guard', 'availability_guard')


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _file_digest(path):
    """Independent fresh read; never fed bytes from another operation."""
    with open(path, 'rb') as handle:
        raw = handle.read()
    return raw, hashlib.sha256(raw).hexdigest()


def _safe_relative(path):
    if not isinstance(path, str) or not path:
        raise ValueError('invalid_replica_path')
    p = Path(path)
    if p.is_absolute() or not p.parts or '..' in p.parts:
        raise ValueError('unsafe_replica_path')
    return path


def _resolve(root, path):
    base = Path(root).resolve()
    target = (base / path).resolve()
    if base != target and base not in target.parents:
        raise ValueError('unsafe_replica_path')
    return base, target


def _latest_run(db):
    run = db.execute('SELECT max(id) AS id FROM run').fetchone()['id']
    if not run:
        raise ValueError('evaluate_first')
    return run


def _is_destroyed(db, subject):
    return bool(db.execute("SELECT 1 FROM execution WHERE subject=? AND action='destroy'", (subject,)).fetchone())


def _frozen(db, run_id, subject):
    row = db.execute('SELECT status FROM decision WHERE run_id=? AND subject=?', (run_id, subject)).fetchone()
    return bool(row and row['status'] == '冻结')


def declare_contract(db_path, subject, guard, source_root, source_path=None):
    """Freeze the per-object protection contract against real source bytes."""
    if guard not in GUARDS:
        raise ValueError('invalid_protection_guard')
    db = connect(db_path)
    try:
        db.executescript(STORAGE_SCHEMA)
        _migrate(db)
        db.executescript(SCHEMA)
        run_id = _latest_run(db)
        if not _frozen(db, run_id, subject):
            raise ValueError('contract_requires_frozen_decision')
        if _is_destroyed(db, subject):
            raise ValueError('storage_object_destroyed')
        if source_path is None:
            batch = db.execute('SELECT config_raw FROM batch ORDER BY id LIMIT 1').fetchone()
            config = json.loads(batch[0])
            if subject not in config['subjects']:
                raise ValueError('unknown_contract_subject')
            source_path = config['subjects'][subject]['path']
        _safe_relative(source_path)
        _, source = _resolve(source_root, source_path)
        if not source.is_file():
            raise ValueError('source_file_missing')
        raw, source_digest = _file_digest(source)
        size = len(raw)
        contract_digest = _digest([subject, guard, run_id, source_path, source_digest, size])
        old = db.execute('SELECT * FROM protection_contract WHERE subject=?', (subject,)).fetchone()
        if old:
            if old['guard'] != guard:
                raise ValueError('contract_guard_immutable')
            if old['source_path'] != source_path or old['source_digest'] != source_digest or old['bytes'] != size:
                raise ValueError('contract_identity_conflict')
            if old['run_id'] == run_id:
                return dict(old)
            # A newer adjudication run exists: rebind only after re-reading the
            # bytes; the guard itself can never be silently swapped.
            with db:
                db.execute('UPDATE protection_contract SET run_id=?,contract_digest=? WHERE subject=?',
                           (run_id, contract_digest, subject))
            return dict(db.execute('SELECT * FROM protection_contract WHERE subject=?', (subject,)).fetchone())
        with db:
            db.execute('INSERT INTO protection_contract VALUES (?,?,?,?,?,?,?)',
                       (subject, guard, run_id, source_path, source_digest, size, contract_digest))
        return dict(db.execute('SELECT * FROM protection_contract WHERE subject=?', (subject,)).fetchone())
    finally:
        db.close()


def _reservation_id(subject, pool_id, target_path):
    return 'rsv-' + _digest([subject, pool_id, target_path])[:24]


def reserve_replica(db_path, subject, pool_id, target_path, source_root):
    """Book pool capacity against a concrete file path before any bytes land."""
    _safe_relative(target_path)
    db = connect(db_path)
    try:
        db.executescript(STORAGE_SCHEMA)
        _migrate(db)
        db.executescript(SCHEMA)
        db.execute('BEGIN IMMEDIATE')
        try:
            run_id = _latest_run(db)
            contract = db.execute('SELECT * FROM protection_contract WHERE subject=?', (subject,)).fetchone()
            if not contract:
                raise ValueError('contract_required')
            if contract['run_id'] != run_id:
                raise ValueError('contract_decision_stale')
            if not _frozen(db, run_id, subject):
                raise ValueError('contract_requires_frozen_decision')
            if _is_destroyed(db, subject):
                raise ValueError('storage_object_destroyed')
            pool = db.execute('SELECT * FROM storage_pool WHERE id=?', (pool_id,)).fetchone()
            if not pool:
                raise ValueError('unknown_storage_pool')
            if Path(target_path).parts[0] != pool_id:
                raise ValueError('replica_path_pool_mismatch')
            # A path is unique per pool; another object may never inherit it.
            owner = db.execute('SELECT subject FROM replica_reservation WHERE pool_id=? AND target_path=?',
                               (pool_id, target_path)).fetchone()
            if owner and owner['subject'] != subject:
                raise ValueError('replica_path_conflict')
            owner_file = db.execute('SELECT subject FROM replica WHERE file_path=?', (target_path,)).fetchone()
            if owner_file and owner_file['subject'] != subject:
                raise ValueError('replica_path_conflict')
            _, source = _resolve(source_root, contract['source_path'])
            if not source.is_file():
                raise ValueError('source_file_missing')
            raw, source_digest = _file_digest(source)
            if source_digest != contract['source_digest'] or len(raw) != contract['bytes']:
                raise ValueError('source_digest_changed')
            rid = _reservation_id(subject, pool_id, target_path)
            old = db.execute('SELECT * FROM replica_reservation WHERE id=?', (rid,)).fetchone()
            if old:
                if old['state'] == 'rejected':
                    raise ValueError('reservation_rejected_choose_new_path')
                if old['state'] == 'landed':
                    db.commit()
                    return dict(old)
                if old['source_digest'] != source_digest or old['bytes'] != len(raw):
                    raise ValueError('reservation_identity_conflict')
                if old['run_id'] != run_id:
                    raise ValueError('reservation_decision_stale')
                db.commit()
                return dict(old)
            committed = db.execute(
                """SELECT COALESCE(sum(b),0) FROM (
                     SELECT bytes AS b FROM storage_placement WHERE pool_id=?
                     UNION ALL SELECT bytes FROM replica WHERE pool_id=?
                   )""", (pool_id, pool_id)).fetchone()[0]
            reserved = db.execute(
                "SELECT COALESCE(sum(bytes),0) FROM replica_reservation WHERE pool_id=? AND state='reserved'",
                (pool_id,)).fetchone()[0]
            if committed + reserved + len(raw) > pool['capacity_bytes']:
                raise ValueError('storage_pool_full')
            digest = _digest([subject, pool_id, target_path, run_id, source_digest, len(raw)])
            with db:
                db.execute('INSERT INTO replica_reservation(id,subject,pool_id,failure_domain,run_id,bytes,'
                           'source_digest,source_path,target_path,state,attempts,digest) VALUES (?,?,?,?,?,?,?,?,?,?,1,?)',
                           (rid, subject, pool_id, pool['failure_domain'], run_id, len(raw),
                            source_digest, contract['source_path'], target_path, 'reserved', digest))
            db.commit()
            return dict(db.execute('SELECT * FROM replica_reservation WHERE id=?', (rid,)).fetchone())
        except Exception:
            db.rollback()
            raise
    finally:
        db.close()


def land_replica(db_path, reservation_id, storage_root):
    """Land bytes first, verify by an independent re-read, register last."""
    db = connect(db_path)
    try:
        db.executescript(STORAGE_SCHEMA)
        _migrate(db)
        db.executescript(SCHEMA)
        db.execute('BEGIN IMMEDIATE')
        try:
            rsv = db.execute('SELECT * FROM replica_reservation WHERE id=?', (reservation_id,)).fetchone()
            if not rsv:
                raise ValueError('unknown_reservation')
            if rsv['state'] == 'rejected':
                raise ValueError('reservation_rejected_choose_new_path')
            if rsv['state'] == 'landed':
                existing = db.execute('SELECT * FROM replica WHERE reservation_id=?', (reservation_id,)).fetchone()
                db.commit()
                return dict(existing) if existing else dict(rsv)
            run_id = _latest_run(db)
            if rsv['run_id'] != run_id:
                raise ValueError('reservation_decision_stale')
            if not _frozen(db, run_id, rsv['subject']):
                raise ValueError('contract_requires_frozen_decision')
            if _is_destroyed(db, rsv['subject']):
                raise ValueError('storage_object_destroyed')
            pool = db.execute('SELECT * FROM storage_pool WHERE id=?', (rsv['pool_id'],)).fetchone()
            committed = db.execute(
                """SELECT COALESCE(sum(b),0) FROM (
                     SELECT bytes AS b FROM storage_placement WHERE pool_id=?
                     UNION ALL SELECT bytes FROM replica WHERE pool_id=?
                   )""", (rsv['pool_id'], rsv['pool_id'])).fetchone()[0]
            reserved = db.execute(
                "SELECT COALESCE(sum(bytes),0) FROM replica_reservation WHERE pool_id=? AND state='reserved' AND id<>?",
                (rsv['pool_id'], reservation_id)).fetchone()[0]
            if committed + reserved + rsv['bytes'] > pool['capacity_bytes']:
                raise ValueError('storage_pool_full')
            base, target = _resolve(storage_root, rsv['target_path'])
            source_base, source = _resolve(storage_root, rsv['source_path'])
            if not source.is_file():
                raise ValueError('source_file_missing')
            raw, source_digest = _file_digest(source)
            if source_digest != rsv['source_digest'] or len(raw) != rsv['bytes']:
                raise ValueError('source_digest_changed')
            part = target.with_name(target.name + '.part.' + reservation_id[:12])
            if target.exists():
                # Replay after a crash between rename and ledger commit.
                landed_raw, landed_digest = _file_digest(target)
                if landed_digest != rsv['source_digest'] or len(landed_raw) != rsv['bytes']:
                    target.rename(target.with_name(target.name + '.tampered.' + str(rsv['attempts'])))
                    db.execute("UPDATE replica_reservation SET state='rejected',attempts=attempts+1,"
                               "updated_at=CURRENT_TIMESTAMP WHERE id=?", (reservation_id,))
                    db.commit()
                    raise ValueError('replica_digest_mismatch')
            else:
                if part.exists():
                    _, part_digest = _file_digest(part)
                    if part_digest != rsv['source_digest']:
                        part.unlink()  # interrupted partial write; start over
                if not part.exists():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with open(part, 'wb') as handle:
                        handle.write(raw)
                # Independent verification of the landed bytes themselves.
                landed_raw, landed_digest = _file_digest(part)
                if landed_digest != rsv['source_digest'] or len(landed_raw) != rsv['bytes']:
                    part.unlink()
                    db.execute("UPDATE replica_reservation SET state='rejected',attempts=attempts+1,"
                               "updated_at=CURRENT_TIMESTAMP WHERE id=?", (reservation_id,))
                    db.commit()
                    raise ValueError('replica_digest_mismatch')
                part.rename(target)
                # Re-read through the final path before trusting the rename.
                landed_raw, landed_digest = _file_digest(target)
                if landed_digest != rsv['source_digest'] or len(landed_raw) != rsv['bytes']:
                    target.rename(target.with_name(target.name + '.tampered.' + str(rsv['attempts'])))
                    db.execute("UPDATE replica_reservation SET state='rejected',attempts=attempts+1,"
                               "updated_at=CURRENT_TIMESTAMP WHERE id=?", (reservation_id,))
                    db.commit()
                    raise ValueError('replica_digest_mismatch')
            now = datetime.now(timezone.utc).isoformat()
            cur = db.execute('INSERT INTO replica(subject,pool_id,failure_domain,run_id,reservation_id,file_path,'
                             'bytes,source_digest,verified_digest,verified_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
                             (rsv['subject'], rsv['pool_id'], pool['failure_domain'], run_id, reservation_id,
                              rsv['target_path'], rsv['bytes'], rsv['source_digest'], landed_digest, now))
            replica_id = cur.lastrowid
            db.execute('INSERT INTO replica_verification(replica_id,run_id,readable,digest,bytes,at) VALUES (?,?,1,?,?,?)',
                       (replica_id, run_id, landed_digest, rsv['bytes'], now))
            db.execute("UPDATE replica_reservation SET state='landed',updated_at=CURRENT_TIMESTAMP WHERE id=?",
                       (reservation_id,))
            db.commit()
            return dict(db.execute('SELECT * FROM replica WHERE id=?', (replica_id,)).fetchone())
        except Exception:
            db.rollback()
            raise
    finally:
        db.close()


def replicate(db_path, subject, pool_id, target_path, source_root, storage_root):
    rsv = reserve_replica(db_path, subject, pool_id, target_path, source_root)
    if rsv['state'] == 'landed':
        row = connect(db_path).execute('SELECT * FROM replica WHERE reservation_id=?', (rsv['id'],)).fetchone()
        return dict(row) if row else rsv
    return land_replica(db_path, rsv['id'], storage_root)


def _capacity_evidence(db):
    rows = db.execute('SELECT * FROM storage_pool ORDER BY id').fetchall()
    evidence = []
    for pool in rows:
        committed = db.execute(
            """SELECT COALESCE(sum(b),0) FROM (
                 SELECT bytes AS b FROM storage_placement WHERE pool_id=?
                 UNION ALL SELECT bytes FROM replica WHERE pool_id=?
               )""", (pool['id'], pool['id'])).fetchone()[0]
        reserved = db.execute(
            "SELECT COALESCE(sum(bytes),0) FROM replica_reservation WHERE pool_id=? AND state='reserved'",
            (pool['id'],)).fetchone()[0]
        evidence.append({'pool_id': pool['id'], 'failure_domain': pool['failure_domain'], 'tier': pool['tier'],
                         'capacity_bytes': pool['capacity_bytes'], 'committed_bytes': committed,
                         'reserved_bytes': reserved,
                         'available_bytes': pool['capacity_bytes'] - committed - reserved})
    return evidence


def adjudicate(db_path, storage_root, subjects=None):
    """Read-only pre-retirement verdict; every replica is re-read from disk.

    Hard blockers (missing/stale contract, unfrozen decision, destroyed source)
    make a verdict impossible -> indeterminate. Damaged or missing replica files
    are still determinable: the object is at_risk, never silently protected.
    """
    db = connect(db_path)
    try:
        db.executescript(STORAGE_SCHEMA)
        _migrate(db)
        db.executescript(SCHEMA)
        run_id = _latest_run(db)
        if subjects is None:
            subjects = [r['subject'] for r in db.execute('SELECT subject FROM protection_contract ORDER BY subject')]
        result = {'run_id': run_id, 'objects': {}}
        for subject in subjects:
            contract = db.execute('SELECT * FROM protection_contract WHERE subject=?', (subject,)).fetchone()
            verdict = {'status': 'indeterminate', 'guard': contract['guard'] if contract else None,
                       'reasons': [], 'failure_domains': [], 'capacity': _capacity_evidence(db),
                       'can_retire_warm': False, 'retire_reasons': []}
            blockers = []
            if not contract:
                blockers.append('no_contract')
            else:
                verdict['guard'] = contract['guard']
                if contract['run_id'] != run_id:
                    blockers.append('contract_decision_stale')
                if not _frozen(db, run_id, subject):
                    blockers.append('decision_not_frozen')
                if _is_destroyed(db, subject):
                    blockers.append('source_destroyed')
            replicas = db.execute('SELECT * FROM replica WHERE subject=? ORDER BY id', (subject,)).fetchall()
            good = []
            for replica in replicas:
                _, target = _resolve(storage_root, replica['file_path'])
                pool = db.execute('SELECT tier FROM storage_pool WHERE id=?', (replica['pool_id'],)).fetchone()
                entry = {'pool_id': replica['pool_id'], 'failure_domain': replica['failure_domain'],
                         'tier': pool['tier'] if pool else None,
                         'file_path': replica['file_path'], 'expected_digest': replica['source_digest'],
                         'digest': None, 'bytes': None, 'state': 'unreadable'}
                try:
                    raw, digest = _file_digest(target)
                    db.execute('INSERT INTO replica_verification(replica_id,run_id,readable,digest,bytes) VALUES (?,?,?,?,?)',
                               (replica['id'], run_id, 1 if digest == replica['source_digest'] else 0,
                                digest, len(raw)))
                    if digest == replica['source_digest'] and len(raw) == replica['bytes']:
                        entry.update({'state': 'good', 'digest': digest, 'bytes': len(raw)})
                        good.append(replica)
                    else:
                        entry.update({'state': 'damaged', 'digest': digest, 'bytes': len(raw)})
                        verdict['reasons'].append(f"digest_mismatch:{replica['file_path']}")
                except OSError:
                    db.execute('INSERT INTO replica_verification(replica_id,run_id,readable,digest,bytes) VALUES (?,?,0,NULL,NULL)',
                               (replica['id'], run_id))
                    verdict['reasons'].append(f"unreadable:{replica['file_path']}")
                verdict['failure_domains'].append(entry)
            db.commit()
            if blockers:
                verdict['reasons'] = blockers + verdict['reasons']
                result['objects'][subject] = verdict
                continue
            good_cold = [r for r in good if db.execute(
                'SELECT tier FROM storage_pool WHERE id=?', (r['pool_id'],)).fetchone()['tier'] == 'cold']
            good_domains = {r['failure_domain'] for r in good}
            cold_domains = {r['failure_domain'] for r in good_cold}
            if contract['guard'] == 'archive_guard':
                satisfied = len(good_cold) >= 1
                if not satisfied:
                    verdict['reasons'].append('no_readable_cold_replica')
            else:
                satisfied = len(good_domains) >= 2
                if not satisfied:
                    verdict['reasons'].append('single_failure_domain_survivors:' + (','.join(sorted(good_domains)) or 'none'))
            verdict['status'] = 'protected' if satisfied else 'at_risk'
            # Retirement removes every warm-tier copy; protection must hold on
            # cold bytes alone, and there must be a warm copy to retire.
            warm_exists = bool(db.execute(
                """SELECT 1 FROM storage_placement p JOIN storage_pool s ON s.id=p.pool_id
                   WHERE p.subject=? AND s.tier='warm'
                   UNION ALL SELECT 1 FROM replica r JOIN storage_pool s ON s.id=r.pool_id
                   WHERE r.subject=? AND s.tier='warm' LIMIT 1""", (subject, subject)).fetchone())
            if not warm_exists:
                verdict['retire_reasons'].append('no_warm_copy')
            if contract['guard'] == 'archive_guard':
                post_retire = len(good_cold) >= 1
            else:
                post_retire = len(cold_domains) >= 2
                if not post_retire:
                    verdict['retire_reasons'].append('cold_domains_below_two:' + (','.join(sorted(cold_domains)) or 'none'))
            verdict['can_retire_warm'] = satisfied and post_retire and warm_exists
            result['objects'][subject] = verdict
        return result
    finally:
        db.close()


def retire_warm(db_path, subject, storage_root):
    """Storage-layer migration only; never a destruction fulfilment."""
    db = connect(db_path)
    try:
        db.executescript(STORAGE_SCHEMA)
        _migrate(db)
        db.executescript(SCHEMA)
        prior = db.execute('SELECT * FROM warm_retirement WHERE subject=?', (subject,)).fetchone()
        if prior:
            return {'subject': subject, 'retired': True, 'replayed': True,
                    'decision': json.loads(prior['decision_json'])}
    finally:
        db.close()
    verdict = adjudicate(db_path, storage_root, [subject])['objects'][subject]
    if not verdict['can_retire_warm']:
        raise ValueError('warm_retirement_not_safe:' + '|'.join(verdict['reasons'] + verdict['retire_reasons']))
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        db.execute('BEGIN IMMEDIATE')
        try:
            warm_replicas = db.execute(
                """SELECT r.* FROM replica r JOIN storage_pool s ON s.id=r.pool_id
                   WHERE r.subject=? AND s.tier='warm'""", (subject,)).fetchall()
            removed = []
            for replica in warm_replicas:
                _, target = _resolve(storage_root, replica['file_path'])
                if target.exists():
                    target.unlink()
                removed.append(replica['file_path'])
                db.execute('DELETE FROM replica_verification WHERE replica_id=?', (replica['id'],))
                db.execute('DELETE FROM replica WHERE id=?', (replica['id'],))
            warm_pools = [r['pool_id'] for r in db.execute(
                "SELECT p.pool_id FROM storage_placement p JOIN storage_pool s ON s.id=p.pool_id "
                "WHERE p.subject=? AND s.tier='warm'", (subject,)).fetchall()]
            db.execute("DELETE FROM storage_placement WHERE subject=? AND pool_id IN ("
                       "SELECT id FROM storage_pool WHERE tier='warm')", (subject,))
            run_id = _latest_run(db)
            guard = db.execute('SELECT guard FROM protection_contract WHERE subject=?', (subject,)).fetchone()['guard']
            digest = db.execute('SELECT source_digest FROM protection_contract WHERE subject=?', (subject,)).fetchone()['source_digest']
            db.execute('INSERT INTO warm_retirement VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)',
                       (subject, run_id, guard, digest, json.dumps(verdict, ensure_ascii=False, sort_keys=True)))
            # Explicit invariant: storage migration never writes a destroy ledger row.
            if db.execute("SELECT 1 FROM execution WHERE subject=? AND action='destroy'", (subject,)).fetchone():
                raise ValueError('retire_must_not_destroy')
            db.commit()
            return {'subject': subject, 'retired': True, 'replayed': False,
                    'removed_files': removed, 'warm_pools': warm_pools, 'decision': verdict}
        except Exception:
            db.rollback()
            raise
    finally:
        db.close()
