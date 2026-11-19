import hashlib
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from retaincase.ingest import initialize, load
from retaincase.rules import evaluate
from retaincase.storage import load_fixture, inventory
from retaincase.replication import (
    adjudicate,
    declare_contract,
    land_replica,
    replicate,
    reserve_replica,
    retire_warm,
)
from retaincase.requests import triage, fulfill
from retaincase.store import connect

FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures'


def ready_db(tmp_path):
    db = tmp_path / 'ledger.db'
    initialize(db, FIXTURES / 'config.json')
    load(db, FIXTURES / 'events.jsonl')
    evaluate(db)
    return db


def seed_files(tmp_path):
    """A synthetic sandbox: source bytes at the root, one directory per pool."""
    root = tmp_path / 'sandbox'
    root.mkdir()
    for name in ('A.bin', 'B.bin'):
        raw = (FIXTURES / 'sandbox' / name).read_bytes()
        (root / name).write_bytes(raw)
    for pool in ('warm-A', 'cold-B', 'cold-C', 'cold-D', 'warm-E', 'tiny'):
        (root / pool).mkdir()
    return root


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def setup(tmp_path, placement=True):
    db = ready_db(tmp_path)
    if placement:
        load_fixture(db, FIXTURES / 'storage-placement.json')
    load_fixture(db, FIXTURES / 'storage-replica-pools.json')
    root = seed_files(tmp_path)
    return db, root


def test_archive_guard_passes_but_availability_fails_when_warm_damaged(tmp_path):
    """The headline counterexample: one damaged warm pool, two contract goals."""
    db, root = setup(tmp_path, placement=False)
    declare_contract(db, 'A', 'archive_guard', root)
    replicate(db, 'A', 'warm-A', 'warm-A/A/warm.bin', root, root)
    replicate(db, 'A', 'cold-B', 'cold-B/A/A.bin', root, root)
    (root / 'warm-A' / 'A' / 'warm.bin').write_bytes(b'corrupted-warm-bytes')

    verdict = adjudicate(db, root, ['A'])['objects']['A']
    states = {x['file_path']: x['state'] for x in verdict['failure_domains']}
    assert states == {'warm-A/A/warm.bin': 'damaged', 'cold-B/A/A.bin': 'good'}
    assert verdict['status'] == 'protected'
    assert any(r.startswith('digest_mismatch:warm-A') for r in verdict['reasons'])
    assert verdict['can_retire_warm'] is True

    # Same physical situation under an availability contract must fail.
    db2 = tmp_path / 'other' / 'ledger.db'
    db2.parent.mkdir()
    initialize(db2, FIXTURES / 'config.json')
    load(db2, FIXTURES / 'events.jsonl')
    evaluate(db2)
    load_fixture(db2, FIXTURES / 'storage-replica-pools.json')
    declare_contract(db2, 'B', 'availability_guard', root)
    replicate(db2, 'B', 'warm-E', 'warm-E/B/warm.bin', root, root)
    replicate(db2, 'B', 'cold-B', 'cold-B/B/B.bin', root, root)
    (root / 'warm-E' / 'B' / 'warm.bin').write_bytes(b'corrupted-warm-bytes')

    verdict_b = adjudicate(db2, root, ['B'])['objects']['B']
    assert verdict_b['status'] == 'at_risk'
    assert any(r.startswith('single_failure_domain_survivors:zone-cold') for r in verdict_b['reasons'])
    assert verdict_b['can_retire_warm'] is False


def test_when_cold_replica_also_corrupt_neither_contract_is_satisfied(tmp_path):
    db, root = setup(tmp_path, placement=False)
    declare_contract(db, 'A', 'archive_guard', root)
    replicate(db, 'A', 'warm-A', 'warm-A/A/warm.bin', root, root)
    cold = replicate(db, 'A', 'cold-B', 'cold-B/A/A.bin', root, root)
    (root / 'warm-A' / 'A' / 'warm.bin').write_bytes(b'x')
    (root / 'cold-B' / 'A' / 'A.bin').write_bytes(b'y')

    verdict = adjudicate(db, root, ['A'])['objects']['A']
    assert verdict['status'] == 'at_risk'
    assert 'no_readable_cold_replica' in verdict['reasons']
    assert {x['state'] for x in verdict['failure_domains']} == {'damaged'}
    assert verdict['can_retire_warm'] is False
    # The bad digest was independently recorded, not trusted from copy_count.
    con = connect(db)
    assert con.execute('SELECT min(readable) FROM replica_verification').fetchone()[0] == 0


def test_two_replicas_in_one_failure_domain_are_not_independent(tmp_path):
    db, root = setup(tmp_path, placement=False)
    declare_contract(db, 'A', 'availability_guard', root)
    # cold-B and cold-C share failure domain zone-cold.
    replicate(db, 'A', 'cold-B', 'cold-B/A/A.bin', root, root)
    replicate(db, 'A', 'cold-C', 'cold-C/A/A.bin', root, root)
    verdict = adjudicate(db, root, ['A'])['objects']['A']
    assert verdict['status'] == 'at_risk'
    assert 'single_failure_domain_survivors:zone-cold' in verdict['reasons']

    # A second, genuinely independent domain restores availability.
    replicate(db, 'A', 'cold-D', 'cold-D/A/A.bin', root, root)
    verdict = adjudicate(db, root, ['A'])['objects']['A']
    assert verdict['status'] == 'protected'
    assert {x['failure_domain'] for x in verdict['failure_domains']} == {'zone-cold', 'zone-cold-2'}


def test_concurrent_reservations_cannot_double_book_last_capacity(tmp_path):
    db, root = setup(tmp_path, placement=False)
    from retaincase.storage import register_pool
    register_pool(db, 'tiny', 51, failure_domain='zone-tiny', tier='cold')
    con = connect(db)
    con.execute("UPDATE storage_pool SET capacity_bytes=51 WHERE id='tiny'")
    con.commit()
    con.close()
    declare_contract(db, 'A', 'archive_guard', root)
    errors = []

    def reserve(target):
        try:
            reserve_replica(db, 'A', 'tiny', f'tiny/A/{target}', root)
        except ValueError as exc:
            errors.append(str(exc))

    t1 = threading.Thread(target=reserve, args=('one.bin',))
    t2 = threading.Thread(target=reserve, args=('two.bin',))
    t1.start(); t2.start(); t1.join(); t2.join()

    assert errors == ['storage_pool_full']
    con = connect(db)
    rows = con.execute("SELECT * FROM replica_reservation WHERE pool_id='tiny'").fetchall()
    assert len(rows) == 1 and rows[0]['state'] == 'reserved' and rows[0]['bytes'] == 51
    evidence = next(p for p in adjudicate(db, root, ['A'])['objects']['A']['capacity']
                    if p['pool_id'] == 'tiny')
    assert evidence['reserved_bytes'] == 51 and evidence['available_bytes'] == 0


def test_landed_tampered_file_is_quarantined_and_never_registered(tmp_path):
    db, root = setup(tmp_path, placement=False)
    declare_contract(db, 'A', 'archive_guard', root)
    rsv = reserve_replica(db, 'A', 'cold-B', 'cold-B/A/A.bin', root)
    target = root / 'cold-B' / 'A' / 'A.bin'
    target.parent.mkdir(parents=True)
    target.write_bytes(b'planted-before-landing')
    with pytest.raises(ValueError, match='replica_digest_mismatch'):
        land_replica(db, rsv['id'], root)
    assert not target.exists()  # quarantined under a different name
    assert list((root / 'cold-B' / 'A').glob('*.tampered.*'))
    con = connect(db)
    assert con.execute("SELECT state FROM replica_reservation WHERE id=?", (rsv['id'],)).fetchone()['state'] == 'rejected'
    assert con.execute('SELECT count(*) FROM replica').fetchone()[0] == 0
    # Capacity is released once the attempt is rejected, so a fresh path works.
    with pytest.raises(ValueError, match='reservation_rejected_choose_new_path'):
        reserve_replica(db, 'A', 'cold-B', 'cold-B/A/A.bin', root)
    with pytest.raises(ValueError, match='reservation_rejected_choose_new_path'):
        land_replica(db, rsv['id'], root)
    retry = reserve_replica(db, 'A', 'cold-B', 'cold-B/A/retry.bin', root)
    landed = land_replica(db, retry['id'], root)
    assert landed['verified_digest'] == digest(root / 'A.bin')


def test_interrupted_move_is_replayable_without_double_booking(tmp_path):
    db, root = setup(tmp_path, placement=False)
    declare_contract(db, 'A', 'archive_guard', root)
    rsv = reserve_replica(db, 'A', 'cold-B', 'cold-B/A/A.bin', root)
    target = root / 'cold-B' / 'A' / 'A.bin'
    part = target.with_name('A.bin.part.' + rsv['id'][:12])
    part.parent.mkdir(parents=True)
    part.write_bytes(b'truncated')  # crash while the part file was being written

    first = land_replica(db, rsv['id'], root)  # rewrites part, verifies, renames
    assert target.read_bytes() == (root / 'A.bin').read_bytes()
    assert not part.exists()
    # Replaying the full reservation+landing flow confirms the existing replica.
    again_rsv = reserve_replica(db, 'A', 'cold-B', 'cold-B/A/A.bin', root)
    assert again_rsv['id'] == rsv['id'] and again_rsv['state'] == 'landed'
    again = land_replica(db, rsv['id'], root)
    assert again['id'] == first['id']
    con = connect(db)
    assert con.execute('SELECT count(*) FROM replica').fetchone()[0] == 1
    pool = next(p for p in adjudicate(db, root, ['A'])['objects']['A']['capacity']
                if p['pool_id'] == 'cold-B')
    assert pool['committed_bytes'] == 51 and pool['reserved_bytes'] == 0


def test_crash_between_rename_and_commit_still_registers(tmp_path):
    db, root = setup(tmp_path, placement=False)
    declare_contract(db, 'A', 'archive_guard', root)
    rsv = reserve_replica(db, 'A', 'cold-D', 'cold-D/A/A.bin', root)
    target = root / 'cold-D' / 'A' / 'A.bin'
    target.parent.mkdir(parents=True)
    target.write_bytes((root / 'A.bin').read_bytes())  # rename done, ledger not yet
    landed = land_replica(db, rsv['id'], root)
    assert landed['verified_digest'] == digest(target)
    assert connect(db).execute('SELECT count(*) FROM replica').fetchone()[0] == 1


def test_decision_change_stales_contract_then_rebinds_without_losing_history(tmp_path):
    db, root = setup(tmp_path)
    contract = declare_contract(db, 'A', 'archive_guard', root)
    replicate(db, 'A', 'cold-B', 'cold-B/A/A.bin', root, root)
    replica_run = connect(db).execute('SELECT run_id FROM replica').fetchone()['run_id']

    # The chosen protection goal is immutable for the life of the object.
    with pytest.raises(ValueError, match='contract_guard_immutable'):
        declare_contract(db, 'A', 'availability_guard', root)

    # A new adjudication run freezes the same status but invalidates the binding.
    evaluate(db)
    assert connect(db).execute('SELECT max(id) FROM run').fetchone()[0] == 2
    with pytest.raises(ValueError, match='contract_decision_stale'):
        reserve_replica(db, 'A', 'cold-D', 'cold-D/A/A.bin', root)
    stale = adjudicate(db, root, ['A'])['objects']['A']
    assert stale['status'] == 'indeterminate' and 'contract_decision_stale' in stale['reasons']

    # Re-reading the same bytes under the new run rebinds the same contract;
    # the confirmed replica and its verification trail must survive untouched.
    rebound = declare_contract(db, 'A', 'archive_guard', root)
    assert rebound['run_id'] == 2 and rebound['contract_digest'] != contract['contract_digest']
    verdict = adjudicate(db, root, ['A'])['objects']['A']
    assert verdict['status'] == 'protected'
    con = connect(db)
    assert con.execute('SELECT run_id FROM replica WHERE id=1').fetchone()['run_id'] == replica_run
    assert con.execute('SELECT count(*) FROM replica_verification').fetchone()[0] >= 1

    # A later adjudication run keeps B frozen but already invalidates the
    # binding, so new reservations are refused as stale.
    db3 = tmp_path / 'stale' / 'ledger.db'
    db3.parent.mkdir()
    initialize(db3, FIXTURES / 'config.json')
    load(db3, FIXTURES / 'events.jsonl')
    evaluate(db3)
    load_fixture(db3, FIXTURES / 'storage-replica-pools.json')
    declare_contract(db3, 'B', 'archive_guard', root)
    replicate(db3, 'B', 'cold-B', 'cold-B/B/B.bin', root, root)
    evaluate(db3)
    with pytest.raises(ValueError, match='contract_decision_stale'):
        reserve_replica(db3, 'B', 'cold-D', 'cold-D/B/B.bin', root)
    assert adjudicate(db3, root, ['B'])['objects']['B']['status'] == 'indeterminate'
    con = connect(db3)
    assert con.execute('SELECT count(*) FROM replica WHERE subject=?', ('B',)).fetchone()[0] == 1
    assert con.execute("SELECT count(*) FROM replica_reservation WHERE state='reserved'").fetchone()[0] == 0

    # Releasing the sole hold on a fresh ledger yields a genuinely unfrozen
    # object: contracts cannot be declared there at all.
    db4 = tmp_path / 'released' / 'ledger.db'
    db4.parent.mkdir()
    initialize(db4, FIXTURES / 'config.json')
    load(db4, FIXTURES / 'events.jsonl')
    release = tmp_path / 'release.jsonl'
    release.write_text(json.dumps({'event_key': 'end-1', 'subject': 'B', 'kind': 'hold_end',
                                   'hold_id': 'court-1', 'at': '2026-05-01'}))
    load(db4, release)
    assert evaluate(db4)['B'] == '可销毁'
    with pytest.raises(ValueError, match='contract_requires_frozen_decision'):
        declare_contract(db4, 'B', 'archive_guard', root)


def test_retire_warm_is_migration_not_destruction_and_cannot_fulfil_request(tmp_path):
    db, root = setup(tmp_path, placement=False)
    declare_contract(db, 'A', 'archive_guard', root)
    replicate(db, 'A', 'warm-A', 'warm-A/A/warm.bin', root, root)
    replicate(db, 'A', 'cold-B', 'cold-B/A/A.bin', root, root)

    request = triage(db, 'REQ-A', ['A'], '2099-01-01T00:00:00Z')
    assert request['items'][0]['obligation'] == 'defer'

    result = retire_warm(db, 'A', root)
    assert result['retired'] is True and result['removed_files'] == ['warm-A/A/warm.bin']
    assert not (root / 'warm-A' / 'A' / 'warm.bin').exists()
    assert (root / 'A.bin').exists()  # source object untouched
    con = connect(db)
    assert con.execute("SELECT count(*) FROM execution WHERE action='destroy'").fetchone()[0] == 0
    assert con.execute('SELECT count(*) FROM warm_retirement WHERE subject=?', ('A',)).fetchone()[0] == 1

    after = triage(db, 'REQ-A', ['A'], '2099-01-01T00:00:00Z')
    assert after['state'] == 'deferred'
    assert fulfill(db, 'REQ-A')['state'] == 'deferred'
    # Retiring twice replaps to the recorded migration instead of re-executing.
    assert retire_warm(db, 'A', root)['replayed'] is True
    verdict = adjudicate(db, root, ['A'])['objects']['A']
    assert verdict['status'] == 'protected' and verdict['can_retire_warm'] is False
    assert 'no_warm_copy' in verdict['retire_reasons']


def test_retirement_refused_when_post_retirement_protection_fails(tmp_path):
    db, root = setup(tmp_path, placement=False)
    declare_contract(db, 'A', 'availability_guard', root)
    replicate(db, 'A', 'warm-A', 'warm-A/A/warm.bin', root, root)
    replicate(db, 'A', 'cold-B', 'cold-B/A/A.bin', root, root)
    verdict = adjudicate(db, root, ['A'])['objects']['A']
    assert verdict['status'] == 'protected' and verdict['can_retire_warm'] is False
    assert any(r.startswith('cold_domains_below_two') for r in verdict['retire_reasons'])
    with pytest.raises(ValueError, match='warm_retirement_not_safe'):
        retire_warm(db, 'A', root)
    assert (root / 'warm-A' / 'A' / 'warm.bin').exists()


def test_destroyed_source_cannot_be_declared_or_adjudicated_protected(tmp_path):
    db, root = setup(tmp_path)
    con = connect(db)
    run = con.execute('SELECT max(id) FROM run').fetchone()[0]
    with con:
        con.execute("INSERT INTO execution(run_id,subject,action,before_hash,after_state) VALUES (?,?,?,?,?)",
                    (run, 'A', 'destroy', 'synthetic', 'absent'))
    with pytest.raises(ValueError, match='storage_object_destroyed'):
        declare_contract(db, 'A', 'archive_guard', root)

    # And an existing contract becomes indeterminate once the source is gone.
    con = connect(db)
    with con:
        con.execute("DELETE FROM execution WHERE subject='A'")
    declare_contract(db, 'B', 'archive_guard', root)
    replicate(db, 'B', 'cold-B', 'cold-B/B/B.bin', root, root)
    with con:
        con.execute("INSERT INTO execution(run_id,subject,action,before_hash,after_state) VALUES (?,?,?,?,?)",
                    (run, 'B', 'destroy', 'synthetic', 'absent'))
    verdict = adjudicate(db, root, ['B'])['objects']['B']
    assert verdict['status'] == 'indeterminate' and 'source_destroyed' in verdict['reasons']
    with pytest.raises(ValueError, match='storage_object_destroyed'):
        reserve_replica(db, 'B', 'cold-D', 'cold-D/B/B.bin', root)


def test_target_path_conflict_between_objects_is_rejected(tmp_path):
    db, root = setup(tmp_path, placement=False)
    declare_contract(db, 'A', 'archive_guard', root)
    declare_contract(db, 'B', 'archive_guard', root)
    reserve_replica(db, 'A', 'cold-B', 'cold-B/shared/x.bin', root)
    with pytest.raises(ValueError, match='replica_path_conflict'):
        reserve_replica(db, 'B', 'cold-B', 'cold-B/shared/x.bin', root)


def test_archive_guard_requires_a_cold_tier_replica(tmp_path):
    db, root = setup(tmp_path, placement=False)
    declare_contract(db, 'A', 'archive_guard', root)
    replicate(db, 'A', 'warm-A', 'warm-A/A/one.bin', root, root)
    verdict = adjudicate(db, root, ['A'])['objects']['A']
    assert verdict['status'] == 'at_risk' and 'no_readable_cold_replica' in verdict['reasons']


def test_unreadable_replica_file_is_at_risk_not_trusted(tmp_path):
    db, root = setup(tmp_path, placement=False)
    declare_contract(db, 'A', 'archive_guard', root)
    replicate(db, 'A', 'cold-B', 'cold-B/A/A.bin', root, root)
    (root / 'cold-B' / 'A' / 'A.bin').unlink()
    verdict = adjudicate(db, root, ['A'])['objects']['A']
    assert verdict['status'] == 'at_risk'
    assert 'unreadable:cold-B/A/A.bin' in verdict['reasons']
    assert verdict['failure_domains'][0]['state'] == 'unreadable'


def test_capacity_evidence_counts_placements_replicas_and_reservations(tmp_path):
    db, root = setup(tmp_path)
    declare_contract(db, 'A', 'archive_guard', root)
    reserve_replica(db, 'A', 'cold-B', 'cold-B/A/A.bin', root)
    evidence = {p['pool_id']: p for p in adjudicate(db, root, ['A'])['objects']['A']['capacity']}
    assert evidence['warm-A']['committed_bytes'] == 85
    assert evidence['cold-B']['reserved_bytes'] == 51
    assert evidence['cold-B']['available_bytes'] == 200 - 51


def test_legacy_pool_schema_migrates_to_failure_domains(tmp_path):
    """A ledger built by the placement baseline gains immutable domain columns."""
    db = ready_db(tmp_path)
    con = connect(db)
    con.execute('CREATE TABLE storage_pool(id TEXT PRIMARY KEY, capacity_bytes INTEGER NOT NULL)')
    con.execute("INSERT INTO storage_pool VALUES ('warm-A',100)")
    con.commit()
    con.close()
    pools = {p['id']: p for p in inventory(db)['pools']}
    assert pools['warm-A']['failure_domain'] == 'warm-A'
    assert pools['warm-A']['tier'] == 'warm'
    # Re-registration with a different domain is rejected as an identity change.
    from retaincase.storage import register_pool
    with pytest.raises(ValueError, match='storage_pool_identity_conflict'):
        register_pool(db, 'warm-A', 100, failure_domain='zone-warm', tier='warm')
    root = seed_files(tmp_path)
    declare_contract(db, 'A', 'archive_guard', root)
    # The legacy domain (pool id) differs from any other pool's domain.
    from retaincase.storage import register_pool as rp
    rp(db, 'cold-B', 200, failure_domain='zone-cold', tier='cold')
    replicate(db, 'A', 'cold-B', 'cold-B/A/A.bin', root, root)
    verdict = adjudicate(db, root, ['A'])['objects']['A']
    assert verdict['status'] == 'protected'


def test_source_bytes_changed_before_landing_blocks_replica(tmp_path):
    db, root = setup(tmp_path, placement=False)
    declare_contract(db, 'A', 'archive_guard', root)
    rsv = reserve_replica(db, 'A', 'cold-B', 'cold-B/A/A.bin', root)
    (root / 'A.bin').write_bytes(b'source-bytes-changed-after-reservation')
    with pytest.raises(ValueError, match='source_digest_changed'):
        land_replica(db, rsv['id'], root)
    with pytest.raises(ValueError, match='source_digest_changed'):
        reserve_replica(db, 'A', 'cold-D', 'cold-D/A/A.bin', root)
    # No replica was registered against the wrong bytes.
    assert connect(db).execute('SELECT count(*) FROM replica').fetchone()[0] == 0


def test_unsafe_paths_are_rejected(tmp_path):
    db, root = setup(tmp_path, placement=False)
    declare_contract(db, 'A', 'archive_guard', root)
    for bad in ('../escape.bin', '/abs/path.bin', 'cold-B/../../x.bin'):
        with pytest.raises(ValueError, match='unsafe_replica_path|replica_path_pool_mismatch'):
            reserve_replica(db, 'A', 'cold-B', bad, root)


def test_cli_end_to_end(tmp_path):
    db = ready_db(tmp_path)
    root = seed_files(tmp_path)
    env = dict(os.environ)
    repo = Path(__file__).resolve().parents[1]
    env['PYTHONPATH'] = str(repo) + (os.pathsep + env['PYTHONPATH'] if env.get('PYTHONPATH') else '')
    # No -I here: isolated mode would ignore PYTHONPATH and hide the local package.
    base = [sys.executable, '-B', '-m', 'retaincase']
    subprocess.run(base + ['storage-seed', '--db', str(db), '--fixture',
                           str(FIXTURES / 'storage-placement.json')], check=True, env=env, cwd=repo)
    subprocess.run(base + ['contract-declare', '--db', str(db), '--subject', 'A',
                           '--guard', 'archive_guard', '--source-root', str(root)],
                   check=True, env=env, cwd=Path(__file__).resolve().parents[1])
    out = subprocess.run(base + ['replica-run', '--db', str(db), '--subject', 'A', '--pool', 'cold-B',
                                 '--target', 'cold-B/A/A.bin', '--source-root', str(root),
                                 '--storage-root', str(root)], check=True, capture_output=True, text=True,
                         env=env, cwd=Path(__file__).resolve().parents[1])
    assert 'verified_digest' in out.stdout
    report = tmp_path / 'verdict.json'
    subprocess.run(base + ['adjudge', '--db', str(db), '--storage-root', str(root), '--out', str(report)],
                   check=True, env=env, cwd=Path(__file__).resolve().parents[1])
    assert json.loads(report.read_text(encoding='utf-8'))['objects']['A']['status'] == 'protected'
    subprocess.run(base + ['retire-warm', '--db', str(db), '--subject', 'A', '--storage-root', str(root)],
                   check=True, env=env, cwd=Path(__file__).resolve().parents[1])
