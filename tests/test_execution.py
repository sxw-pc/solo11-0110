"""Recoverable multi-object local destruction: interruption and recovery."""
import hashlib
import json
import threading

import pytest

from retaincase import execution
from retaincase.execution import (Interruption, describe, execute, pending_attempts,
                                  recover, verify)
from retaincase.ingest import initialize
from retaincase.requests import fulfill, triage
from retaincase.rules import action, evaluate
from retaincase.store import connect


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


ALPHA, BETA = b'alpha', b'beta'


def make_env(tmp_path, subjects=None, extra=None):
    """A two-object destroyable batch plus a sandbox with real target bytes."""
    subjects = subjects or {
        'A': {'created': '2026-01-01', 'category': 'ordinary', 'path': 'A.bin',
              'sha256': _sha(ALPHA)},
        'B': {'created': '2026-01-01', 'category': 'ordinary', 'path': 'B.bin',
              'sha256': _sha(BETA)},
    }
    config = {'batch_id': 'batch-x', 'rule_version': 'v1', 'as_of': '2026-06-01',
              'policy': {'ordinary': {'start': 'created', 'days': 30}},
              'subjects': subjects}
    if extra:
        config.update(extra)
    cfg = tmp_path / 'config.json'
    cfg.write_text(json.dumps(config), encoding='utf-8')
    db = tmp_path / 'ledger.db'
    initialize(db, cfg)
    evaluate(db)
    plan = tmp_path / 'plan.json'
    action('plan', db, out=plan)
    root = tmp_path / 'sandbox'
    root.mkdir()
    (root / 'A.bin').write_bytes(ALPHA)
    (root / 'B.bin').write_bytes(BETA)
    return db, plan, root


def attempt_id(db):
    rows = pending_attempts(db)
    assert len(rows) == 1, rows
    return rows[0]['id']


def run_interrupted(db, plan, root, policy, point, **context_match):
    holder = {}

    def injector(name, ctx):
        if name != point:
            return
        if all(ctx.get(k) == v for k, v in context_match.items()):
            raise Interruption(name)

    try:
        holder['result'] = execute(db, plan, root, recovery_policy=policy,
                                   injector=injector)
    except Interruption:
        holder['interrupted'] = True
    return holder


# ---------------------------------------------------------------------------
# Two-object recovery routes
# ---------------------------------------------------------------------------

def test_complete_on_recovery_finishes_fully_quarantined_plan(tmp_path):
    db, plan, root = make_env(tmp_path)
    holder = run_interrupted(db, plan, root, 'complete_on_recovery',
                             'after_ledger_commit', phase='quarantined')
    assert holder.get('interrupted')
    aid = attempt_id(db)
    before = describe(db, aid)
    assert before['state'] == 'quarantined'
    assert [o['state'] for o in before['objects']] == ['quarantined', 'quarantined']
    assert verify(db, aid) == []
    assert not (root / 'A.bin').exists() and not (root / 'B.bin').exists()

    after = recover(db, aid)
    assert after['state'] == 'complete' and after['fulfilled'] is True
    assert {p['subject'] for p in after['proofs']} == {'A', 'B'}
    assert [o['state'] for o in after['objects']] == ['destroyed', 'destroyed']
    assert verify(db, aid) == []
    assert not (root / 'A.bin').exists() and not (root / 'B.bin').exists()


def test_restore_on_recovery_puts_every_object_back_hash_checked(tmp_path):
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'restore_on_recovery',
                    'after_ledger_commit', phase='quarantined')
    aid = attempt_id(db)
    after = recover(db, aid)
    assert after['state'] == 'restored' and after['fulfilled'] is False
    assert after['proofs'] == []
    assert (root / 'A.bin').read_bytes() == ALPHA
    assert (root / 'B.bin').read_bytes() == BETA
    assert verify(db, aid) == []
    # No final proof may be synthesized from a restored attempt.
    assert execution.destruction_proofs(db, after['run_id'], 'A') == []


def test_partial_isolation_never_claims_completion_for_either_route(tmp_path):
    for policy in ('complete_on_recovery', 'restore_on_recovery'):
        base = tmp_path / policy
        base.mkdir()
        db, plan, root = make_env(base)
        run_interrupted(db, plan, root, policy, 'after_quarantine', subject='A')
        aid = attempt_id(db)
        before = describe(db, aid)
        assert [(o['subject'], o['state']) for o in before['objects']] == [
            ('A', 'quarantined'), ('B', 'pending')]
        assert verify(db, aid) == []

        after = recover(db, aid)
        assert after['state'] == 'partial', policy
        assert after['fulfilled'] is False
        assert after['proofs'] == []
        # A was restored from quarantine; B was never moved and is untouched.
        assert (root / 'A.bin').read_bytes() == ALPHA
        assert (root / 'B.bin').read_bytes() == BETA
        assert verify(db, aid) == []
        assert execution.destruction_proofs(db, after['run_id'], 'A') == []
        assert execution.destruction_proofs(db, after['run_id'], 'B') == []


def test_partial_isolation_never_destroys_isolated_object(tmp_path):
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'complete_on_recovery',
                    'after_quarantine', subject='A')
    aid = attempt_id(db)
    recover(db, aid)
    assert execution.destruction_proofs(db, describe(db, aid)['run_id'], 'A') == []
    assert (root / 'A.bin').exists() and (root / 'B.bin').exists()
    # Nothing was left behind in quarantine either.
    leftovers = [p for p in (root / execution.QUARANTINE_DIR).rglob('*.bin')]
    assert leftovers == []


# ---------------------------------------------------------------------------
# Disposition-phase interruptions
# ---------------------------------------------------------------------------

def test_interruption_after_one_proof_keeps_prior_proof_and_finishes(tmp_path):
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'complete_on_recovery',
                    'during_disposition', phase='after_proof', subject='A')
    aid = attempt_id(db)
    mid = describe(db, aid)
    assert mid['state'] == 'disposing'
    states = {o['subject']: o['state'] for o in mid['objects']}
    assert states == {'A': 'destroyed', 'B': 'quarantined'}
    assert [p['subject'] for p in mid['proofs']] == ['A']
    assert verify(db, aid) == []

    done = recover(db, aid)
    assert done['state'] == 'complete'
    assert {p['subject'] for p in done['proofs']} == {'A', 'B'}
    assert verify(db, aid) == []
    assert not (root / 'A.bin').exists() and not (root / 'B.bin').exists()


def test_interruption_between_unlink_and_proof_completes_from_journal(tmp_path):
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'complete_on_recovery',
                    'during_disposition', phase='after_unlink', subject='A')
    aid = attempt_id(db)
    mid = describe(db, aid)
    assert {o['subject']: o['state'] for o in mid['objects']}['A'] == 'destroying'
    # The bytes are gone, but there is no proof yet: never report fulfilment.
    assert mid['proofs'] == []
    assert verify(db, aid) == []

    done = recover(db, aid)
    assert done['state'] == 'complete'
    assert {p['subject'] for p in done['proofs']} == {'A', 'B'}
    assert verify(db, aid) == []


def test_restore_interruption_resumes_without_double_move(tmp_path):
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'restore_on_recovery',
                    'after_restore', subject='A')
    aid = attempt_id(db)
    mid = describe(db, aid)
    assert mid['state'] == 'restoring'
    assert (root / 'A.bin').read_bytes() == ALPHA
    assert verify(db, aid) == []

    done = recover(db, aid)
    assert done['state'] == 'restored'
    assert (root / 'A.bin').read_bytes() == ALPHA
    assert (root / 'B.bin').read_bytes() == BETA
    assert verify(db, aid) == []


# ---------------------------------------------------------------------------
# Pre-flight and crash-before-work
# ---------------------------------------------------------------------------

def test_nothing_is_moved_if_any_target_fails_preflight(tmp_path):
    db, plan, root = make_env(tmp_path)
    (root / 'B.bin').write_bytes(b'tampered')
    with pytest.raises(ValueError, match='hash_changed:B'):
        execute(db, plan, root)
    assert (root / 'A.bin').read_bytes() == ALPHA
    assert (root / 'B.bin').read_bytes() == b'tampered'
    assert pending_attempts(db) == []
    con = connect(db)
    assert con.execute('SELECT count(*) FROM execution_attempt').fetchone()[0] == 0
    assert con.execute('SELECT count(*) FROM execution_proof').fetchone()[0] == 0
    con.close()


def test_missing_target_is_not_treated_as_erasure_proof(tmp_path):
    db, plan, root = make_env(tmp_path)
    triage(db, 'REQ', ['A'], '2099-01-01T00:00:00Z')
    (root / 'A.bin').unlink()
    with pytest.raises(ValueError, match='target_missing:A'):
        execute(db, plan, root)
    result = fulfill(db, 'REQ')
    assert result['missing_execution'] == ['A']
    assert result['state'] != 'fulfilled'


def test_interrupt_before_attempt_commit_leaves_no_trace(tmp_path):
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'complete_on_recovery', 'before_commit')
    assert pending_attempts(db) == []
    assert (root / 'A.bin').read_bytes() == ALPHA
    assert (root / 'B.bin').read_bytes() == BETA
    assert recover(db, sandbox=root)['state'] == 'none'


def test_interrupt_after_attempt_commit_before_moves_is_partial(tmp_path):
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'complete_on_recovery', 'after_commit')
    aid = attempt_id(db)
    assert [o['state'] for o in describe(db, aid)['objects']] == ['pending', 'pending']
    assert verify(db, aid) == []
    after = recover(db, aid)
    assert after['state'] == 'partial'
    assert (root / 'A.bin').read_bytes() == ALPHA
    assert (root / 'B.bin').read_bytes() == BETA
    assert after['proofs'] == []


# ---------------------------------------------------------------------------
# Disputes: corrupt bytes and original-path conflicts
# ---------------------------------------------------------------------------

def test_corrupt_quarantine_bytes_enter_dispute_without_proof(tmp_path):
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'complete_on_recovery',
                    'after_ledger_commit', phase='quarantined')
    aid = attempt_id(db)
    quarantined = {o['subject']: root / o['quarantine_path']
                   for o in describe(db, aid)['objects']}
    quarantined['A'].write_bytes(b'corrupted')

    after = recover(db, aid)
    assert after['state'] == 'disputed'
    assert after['proofs'] == []
    assert {o['subject']: o['state'] for o in after['objects']}['A'] == 'disputed'
    # The damaged bytes are preserved for investigation, not destroyed.
    assert quarantined['A'].read_bytes() == b'corrupted'
    assert execution.destruction_proofs(db, after['run_id'], 'A') == []
    assert any(p.startswith('disputed_quarantine_invalid:A') for p in verify(db, aid))


def test_original_path_occupied_blocks_restore_and_preserves_new_file(tmp_path):
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'restore_on_recovery',
                    'after_ledger_commit', phase='quarantined')
    aid = attempt_id(db)
    (root / 'A.bin').write_bytes(b'newcomer')
    after = recover(db, aid)
    assert after['state'] == 'disputed'
    assert (root / 'A.bin').read_bytes() == b'newcomer'   # never overwritten
    assert {o['subject']: o['state'] for o in after['objects']}['A'] == 'disputed'
    assert after['proofs'] == []
    assert (root / 'B.bin').exists() is False  # B still safely isolated


def test_disputed_attempt_is_not_presented_as_fulfilled(tmp_path):
    db, plan, root = make_env(tmp_path)
    triage(db, 'REQ', ['A', 'B'], '2099-01-01T00:00:00Z')
    run_interrupted(db, plan, root, 'complete_on_recovery',
                    'after_ledger_commit', phase='quarantined')
    aid = attempt_id(db)
    quarantined = {o['subject']: root / o['quarantine_path']
                   for o in describe(db, aid)['objects']}
    quarantined['B'].write_bytes(b'corrupted')
    recover(db, aid)
    result = fulfill(db, 'REQ')
    assert result['state'] != 'fulfilled'
    # The whole attempt is disputed; neither object may count as erased.
    assert result['disputed_execution'] == ['A', 'B']
    assert result['missing_execution'] == []


# ---------------------------------------------------------------------------
# Concurrency and overlapping plans
# ---------------------------------------------------------------------------

def test_concurrent_execution_of_same_plan_serializes(tmp_path):
    db, plan, root = make_env(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    outcome = {}

    def first():
        def injector(name, ctx):
            if name == 'after_commit':
                entered.set()
                assert release.wait(5)
        outcome['first'] = execute(db, plan, root, injector=injector)

    worker = threading.Thread(target=first)
    worker.start()
    assert entered.wait(5)
    with pytest.raises(ValueError, match='sandbox_execution_busy'):
        execute(db, plan, root)
    release.set()
    worker.join(5)
    assert outcome['first']['state'] == 'complete'

    con = connect(db)
    assert con.execute('SELECT count(*) FROM execution_attempt').fetchone()[0] == 1
    assert con.execute('SELECT count(*) FROM execution_proof').fetchone()[0] == 2
    assert con.execute('SELECT count(*) FROM execution_claim').fetchone()[0] == 0
    con.close()
    # An idempotent replay after completion does not double-book.
    replay = execute(db, plan, root)
    assert replay['state'] == 'complete'
    assert replay['newly_destroyed'] == []
    con = connect(db)
    assert con.execute('SELECT count(*) FROM execution_proof').fetchone()[0] == 2
    con.close()


def test_overlapping_plan_cannot_claim_another_attempts_objects(tmp_path):
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'complete_on_recovery',
                    'after_ledger_commit', phase='quarantined')
    aid = attempt_id(db)

    # A distinct, still-authorized plan (same eligible set, different order and
    # therefore a different digest) overlaps on A and B.
    body = json.loads(plan.read_text(encoding='utf-8'))
    reordered = json.dumps(body[::-1], ensure_ascii=False, indent=2)
    other = tmp_path / 'other-plan.json'
    other.write_text(reordered, encoding='utf-8')
    digest = hashlib.sha256(reordered.encode('utf-8')).hexdigest()
    con = connect(db)
    run_id = con.execute('SELECT max(id) FROM run').fetchone()[0]
    with con:
        con.execute('INSERT INTO plan(run_id,digest,body) VALUES (?,?,?)',
                    (run_id, digest, reordered))
    con.close()

    with pytest.raises(ValueError, match='object_claimed_by_other_attempt'):
        execute(db, other, root)

    # The original attempt still owns the isolated bytes and can be recovered.
    assert describe(db, aid)['state'] == 'quarantined'
    done = recover(db, aid)
    assert done['state'] == 'complete'
    con = connect(db)
    assert con.execute('SELECT count(*) FROM execution_proof').fetchone()[0] == 2
    con.close()


def test_new_plan_does_not_inherit_old_quarantine_files(tmp_path):
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'restore_on_recovery',
                    'after_ledger_commit', phase='quarantined')
    aid = attempt_id(db)
    # The attempt is still active; a nonce-forced second attempt must not steal
    # or double-count the isolated bytes.
    with pytest.raises(ValueError, match='object_claimed_by_other_attempt'):
        execute(db, plan, root, recovery_policy='restore_on_recovery', nonce='retry')
    assert describe(db, aid)['state'] == 'quarantined'


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------

def test_recovery_repeats_are_idempotent(tmp_path):
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'complete_on_recovery',
                    'after_ledger_commit', phase='quarantined')
    aid = attempt_id(db)
    first = recover(db, aid)
    second = recover(db, aid)
    third = recover(db, aid)
    assert first['state'] == second['state'] == third['state'] == 'complete'
    assert second['newly_destroyed'] == [] and third['newly_destroyed'] == []
    con = connect(db)
    assert con.execute('SELECT count(*) FROM execution_proof').fetchone()[0] == 2
    assert con.execute('SELECT count(*) FROM execution_attempt').fetchone()[0] == 1
    con.close()
    assert verify(db, aid) == []


def test_restore_recovery_repeats_are_idempotent(tmp_path):
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'restore_on_recovery',
                    'after_ledger_commit', phase='quarantined')
    aid = attempt_id(db)
    recover(db, aid)
    again = recover(db, aid)
    assert again['state'] == 'restored'
    assert (root / 'A.bin').read_bytes() == ALPHA
    assert verify(db, aid) == []


# ---------------------------------------------------------------------------
# Newer decisions
# ---------------------------------------------------------------------------

def test_newer_decision_blocks_destructive_completion_and_restores(tmp_path):
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'complete_on_recovery',
                    'after_ledger_commit', phase='quarantined')
    aid = attempt_id(db)

    # A new hold arrives after the attempt was frozen; re-evaluation supersedes
    # the old decision set.
    extra = tmp_path / 'hold.jsonl'
    extra.write_text(json.dumps({'event_key': 'late-hold', 'subject': 'A',
                                 'kind': 'hold_start', 'hold_id': 'court-late',
                                 'at': '2026-05-01'}), encoding='utf-8')
    from retaincase.ingest import load
    load(db, extra)
    assert evaluate(db)['A'] == '冻结'

    after = recover(db, aid)
    assert after['state'] == 'stale'
    assert after['fulfilled'] is False
    assert after['proofs'] == []
    # The quarantined bytes were restored; the new hold is never relaxed.
    assert (root / 'A.bin').read_bytes() == ALPHA
    assert (root / 'B.bin').read_bytes() == BETA
    assert verify(db, aid) == []
    assert execution.destruction_proofs(db, after['run_id'], 'A') == []


def test_old_attempt_of_older_run_is_not_completed_after_reevaluation(tmp_path):
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'complete_on_recovery',
                    'after_quarantine', subject='A')
    aid = attempt_id(db)
    evaluate(db)  # a new run, same conclusions
    after = recover(db, aid)
    assert after['state'] == 'partial'
    assert after['proofs'] == []
    assert (root / 'A.bin').read_bytes() == ALPHA


# ---------------------------------------------------------------------------
# Legacy compatibility
# ---------------------------------------------------------------------------

def test_legacy_execution_rows_are_display_only(tmp_path):
    db, plan, root = make_env(tmp_path)
    con = connect(db)
    run_id = con.execute('SELECT max(id) FROM run').fetchone()[0]
    with con:
        con.execute("INSERT INTO execution(run_id,subject,action,before_hash,"
                    "after_state) VALUES (?,?,?,?,?)",
                    (run_id, 'A', 'destroy', _sha(ALPHA), 'absent'))
    con.close()

    # Legacy rows are never new-protocol recoverable evidence.
    assert execution.destruction_proofs(db, run_id, 'A') == []
    assert execution.pending_proofs(db, run_id, 'A') is False

    from retaincase.report import export
    report = json.loads(export(db, tmp_path / 'report.json').read_text(encoding='utf-8'))
    legacy = [x for x in report['executions'] if x['subject'] == 'A']
    assert legacy and legacy[0]['protocol'] == 'legacy'
    assert legacy[0]['recoverable'] is False
    assert report['execution_attempts'] == []

    # A genuine attempt records its own proof and its own attempt row.
    execute(db, plan, root)
    assert execution.destruction_proofs(db, run_id, 'A')
    report = json.loads(export(db, tmp_path / 'report2.json').read_text(encoding='utf-8'))
    assert len(report['execution_attempts']) == 1


def test_legacy_row_does_not_satisfy_a_new_protocol_partial_attempt(tmp_path):
    db, plan, root = make_env(tmp_path)
    triage(db, 'REQ', ['A', 'B'], '2099-01-01T00:00:00Z')
    con = connect(db)
    run_id = con.execute('SELECT max(id) FROM run').fetchone()[0]
    with con:
        con.execute("INSERT INTO execution(run_id,subject,action,before_hash,"
                    "after_state) VALUES (?,?,?,?,?)",
                    (run_id, 'A', 'destroy', _sha(ALPHA), 'absent'))
    con.close()
    run_interrupted(db, plan, root, 'restore_on_recovery',
                    'after_quarantine', subject='A')
    aid = attempt_id(db)
    mid = fulfill(db, 'REQ')
    assert mid['pending_local_execution'] == ['A', 'B']
    assert mid['state'] != 'fulfilled'
    recover(db, aid)
    final = fulfill(db, 'REQ')
    # The attempt now exists for A, so new-protocol evidence is authoritative:
    # the pre-existing legacy row may no longer stand in for A, and B has no
    # evidence at all.
    assert final['missing_execution'] == ['A', 'B']
    assert final['state'] != 'fulfilled'


# ---------------------------------------------------------------------------
# Request fulfilment and custody boundary
# ---------------------------------------------------------------------------

def test_fulfilment_waits_for_final_proof_and_then_consumes_it(tmp_path):
    db, plan, root = make_env(tmp_path)
    triage(db, 'REQ', ['A', 'B'], '2099-01-01T00:00:00Z')
    run_interrupted(db, plan, root, 'complete_on_recovery',
                    'after_ledger_commit', phase='quarantined')
    aid = attempt_id(db)
    waiting = fulfill(db, 'REQ')
    assert waiting['state'] != 'fulfilled'
    assert waiting['pending_local_execution'] == ['A', 'B']
    assert waiting['missing_execution'] == []

    recover(db, aid)
    done = fulfill(db, 'REQ')
    assert done['state'] == 'fulfilled'


def test_restored_attempt_keeps_request_unfulfilled(tmp_path):
    db, plan, root = make_env(tmp_path)
    triage(db, 'REQ', ['A', 'B'], '2099-01-01T00:00:00Z')
    run_interrupted(db, plan, root, 'restore_on_recovery',
                    'after_ledger_commit', phase='quarantined')
    recover(db, attempt_id(db))
    result = fulfill(db, 'REQ')
    assert result['state'] != 'fulfilled'
    assert result['missing_execution'] == ['A', 'B']


def test_custody_handoff_blocked_while_bytes_are_isolated(tmp_path):
    from retaincase.handoff import prepare
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'complete_on_recovery',
                    'after_ledger_commit', phase='quarantined')
    with pytest.raises(ValueError, match='local_execution_in_progress:A'):
        prepare(db, 'T', 'receiver-A', ['A'], '2099-01-01T00:00:00Z')
    assert execution.blocked_subject(db, 'A') == 'quarantined'


def test_remote_obligations_still_use_receipts(tmp_path):
    """Local isolation never substitutes for an accepted custody recall."""
    from retaincase.handoff import acknowledge, prepare
    from retaincase.recall import open_case
    db, plan, root = make_env(tmp_path)
    prepare(db, 'T', 'receiver-A', ['A'], '2099-01-01T00:00:00Z')
    acknowledge(db, 'T', 'receiver-A', {'A': _sha(ALPHA)}, '2030-01-01T00:00:00Z')
    triage(db, 'REQ', ['A'], '2099-01-01T00:00:00Z')
    open_case(db, 'RC', 'REQ', 'T')
    # Even a completed local attempt does not satisfy a remote obligation.
    execute(db, plan, root)
    result = fulfill(db, 'REQ')
    assert result['state'] != 'fulfilled'
    assert result['missing_remote_receipt'] == ['A']


# ---------------------------------------------------------------------------
# Verification across states
# ---------------------------------------------------------------------------

def test_verify_detects_tampered_evidence_rows(tmp_path):
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'complete_on_recovery',
                    'after_ledger_commit', phase='quarantined')
    aid = attempt_id(db)
    con = connect(db)
    with con:
        con.execute("UPDATE execution_attempt SET manifest_digest='x' WHERE id=?", (aid,))
    con.close()
    assert 'manifest_tampered' in verify(db, aid)


def test_verify_reports_impossible_destroyed_state(tmp_path):
    db, plan, root = make_env(tmp_path)
    execute(db, plan, root)
    aid = connect(db).execute('SELECT id FROM execution_attempt').fetchone()[0]
    con = connect(db)
    with con:
        con.execute("DELETE FROM execution_proof WHERE attempt_id=?", (aid,))
    con.close()
    problems = verify(db, aid)
    assert any(p.startswith('proof_missing:A') for p in problems)


def test_policy_is_frozen_at_attempt_start(tmp_path):
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'complete_on_recovery',
                    'after_ledger_commit', phase='quarantined')
    aid = attempt_id(db)
    with pytest.raises(ValueError, match='attempt_policy_conflict'):
        execute(db, plan, root, recovery_policy='restore_on_recovery')
    assert describe(db, aid)['policy'] == 'complete_on_recovery'
    assert describe(db, aid)['state'] == 'quarantined'


def test_recover_requires_known_attempt_or_sandbox(tmp_path):
    db, _, _ = make_env(tmp_path)
    with pytest.raises(ValueError, match='sandbox_or_attempt_required'):
        recover(db)
    with pytest.raises(ValueError, match='unknown_attempt'):
        recover(db, attempt_id='does-not-exist')


def test_tampered_plan_body_is_not_recovered(tmp_path):
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'complete_on_recovery',
                    'after_ledger_commit', phase='quarantined')
    aid = attempt_id(db)
    con = connect(db)
    digest = con.execute('SELECT plan_digest FROM execution_attempt WHERE id=?',
                         (aid,)).fetchone()[0]
    with con:
        con.execute('UPDATE plan SET body=? WHERE digest=?',
                    ('[{"subject": "A"}]', digest))
    con.close()
    after = recover(db, aid)
    assert after['state'] == 'stale'
    assert after['fulfilled'] is False
    assert after['proofs'] == []
    assert 'authorizing_plan_missing' in verify(db, aid)
    # Quarantine bytes stay put; nothing was destroyed or restored.
    assert (root / 'A.bin').exists() is False and (root / 'B.bin').exists() is False


def test_new_latest_run_supersedes_old_attempt_without_destroying(tmp_path):
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'complete_on_recovery',
                    'after_ledger_commit', phase='quarantined')
    aid = attempt_id(db)
    evaluate(db)  # a fresh run; the frozen attempt's run is no longer latest
    assert describe(db, aid)['state'] == 'quarantined'
    after = recover(db, aid)
    assert after['state'] == 'stale'
    assert after['proofs'] == []
    assert (root / 'A.bin').read_bytes() == ALPHA
    assert (root / 'B.bin').read_bytes() == BETA
    assert verify(db, aid) == []


def test_new_plan_cannot_claim_old_attempt_objects_under_latest_run(tmp_path):
    db, plan, root = make_env(tmp_path)
    run_interrupted(db, plan, root, 'complete_on_recovery',
                    'after_quarantine', subject='A')
    aid = attempt_id(db)
    evaluate(db)
    # A genuinely different, authorized plan for the latest run overlaps on A/B.
    body = json.loads(plan.read_text(encoding='utf-8'))
    reordered = json.dumps(body[::-1], ensure_ascii=False, indent=2)
    other = tmp_path / 'other-plan.json'
    other.write_text(reordered, encoding='utf-8')
    digest = hashlib.sha256(reordered.encode('utf-8')).hexdigest()
    con = connect(db)
    latest = con.execute('SELECT max(id) FROM run').fetchone()[0]
    with con:
        con.execute('INSERT INTO plan(run_id,digest,body) VALUES (?,?,?)',
                    (latest, digest, reordered))
    con.close()
    with pytest.raises(ValueError, match='object_claimed_by_other_attempt'):
        execute(db, other, root)
    assert describe(db, aid)['state'] == 'quarantining'

