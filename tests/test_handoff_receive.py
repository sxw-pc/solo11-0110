import json
import sys
from pathlib import Path

import pytest

from retaincase.ingest import initialize, load
from retaincase.rules import evaluate
from retaincase.requests import triage, fulfill
from retaincase.handoff import prepare, receive, acknowledge, inspect
from retaincase.recall import open_case, submit
from retaincase.store import connect

FIX = Path(__file__).resolve().parents[1] / 'fixtures'
D_HASH = '2a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5aea'
E_HASH = '25a724334a3ab02be1e6ab79785cd08ccb98941e9e109fbac2b3f405017888c4'


def ready(tmp_path, with_e=True):
    config = json.loads((FIX / 'config.json').read_text(encoding='utf-8'))
    if with_e:
        config['subjects']['E'] = {
            'created': '2026-01-01', 'category': 'ordinary', 'path': 'E.bin', 'sha256': E_HASH}
    config_path = tmp_path / 'config.json'
    config_path.write_text(json.dumps(config), encoding='utf-8')
    db = tmp_path / 'ledger.db'
    initialize(db, config_path)
    load(db, FIX / 'events.jsonl')
    evaluate(db)
    return db


def cases():
    return json.loads((FIX / 'handoff-receive.json').read_text(encoding='utf-8'))


def receipt_rows(db, transfer_id):
    con = connect(db)
    rows = [dict(r) for r in con.execute(
        'SELECT event_key,subject,verdict,reason FROM custody_receipt WHERE transfer_id=? ORDER BY rowid',
        (transfer_id,))]
    con.close()
    return rows


def item_states(view):
    return {x['subject']: x['receipt_state'] for x in view['items']}


def obligations(result):
    return {x['subject']: x['obligation'] for x in result['items']}


def test_partial_receive_d_only_splits_remote_and_local_obligations(tmp_path):
    """Acceptance scenario: transfer D+E, only D received -> D remote_erase, E erase."""
    db = ready(tmp_path)
    prepare(db, 'T', 'receiver-A', ['D', 'E'], '2099-01-01T00:00:00Z')
    c = cases()['receive_d_only']
    view = receive(db, 'T', 'receiver-A', c['event_key'], c['receipts'], c['at'])
    assert view['state'] == 'prepared'          # whole transfer is not accepted
    assert view['receipt_state'] == 'partial'
    assert item_states(view) == {'D': 'received', 'E': 'pending'}

    result = triage(db, 'REQ', ['D', 'E'], '2099-01-01T00:00:00Z')
    assert obligations(result) == {'D': 'remote_erase', 'E': 'erase'}

    progress = fulfill(db, 'REQ')
    assert progress['missing_remote_receipt'] == ['D']
    assert progress['missing_execution'] == ['E']

    # The recall case may only cover the object the recipient actually holds.
    rc = open_case(db, 'RC', 'REQ', 'T')
    assert [x['subject'] for x in rc['items']] == ['D']

    recall_fixture = json.loads((FIX / 'recall-cases.json').read_text(encoding='utf-8'))
    submit(db, 'RC', 'receiver-A', [recall_fixture['first_batch'][0]])
    progress = fulfill(db, 'REQ')
    assert progress['missing_remote_receipt'] == []
    assert progress['missing_execution'] == ['E']   # E still needs the local ledger

    con = connect(db)
    run = con.execute('SELECT max(id) FROM run').fetchone()[0]
    with con:
        con.execute("INSERT INTO execution(run_id,subject,action,before_hash,after_state) VALUES (?,?,?,?,?)",
                    (run, 'E', 'destroy', E_HASH, 'absent'))
    con.close()
    assert fulfill(db, 'REQ')['state'] == 'fulfilled'


def test_late_receive_after_frozen_request_is_rejected_and_obligation_stands(tmp_path):
    """Chosen route A: post-freeze receive is REJECTED; the frozen local duty is kept."""
    db = ready(tmp_path)
    prepare(db, 'T', 'receiver-A', ['D', 'E'], '2099-01-01T00:00:00Z')
    c = cases()['receive_d_only']
    receive(db, 'T', 'receiver-A', c['event_key'], c['receipts'], c['at'])
    triage(db, 'REQ', ['D', 'E'], '2099-01-01T00:00:00Z')

    late = cases()['late_e_valid']
    view = receive(db, 'T', 'receiver-A', late['event_key'], late['receipts'], late['at'])
    assert item_states(view) == {'D': 'received', 'E': 'pending'}
    row = [r for r in receipt_rows(db, 'T') if r['event_key'] == late['event_key']][0]
    assert row == {'event_key': late['event_key'], 'subject': 'E',
                   'verdict': 'rejected', 'reason': 'erasure_request_frozen'}

    # Replaying the same rejected event is idempotent: still one traceable row.
    receive(db, 'T', 'receiver-A', late['event_key'], late['receipts'], late['at'])
    assert len([r for r in receipt_rows(db, 'T') if r['event_key'] == late['event_key']]) == 1

    # The frozen request keeps E local even after the (rejected) late event.
    assert obligations(triage(db, 'REQ', ['D', 'E'], '2099-01-01T00:00:00Z')) == {
        'D': 'remote_erase', 'E': 'erase'}
    # A recall case over the same transfer still resolves to D alone; E can never
    # enter external proof while its frozen duty is local.
    rc2 = open_case(db, 'RC2', 'REQ', 'T')
    assert [x['subject'] for x in rc2['items']] == ['D']


def test_receive_before_request_freeze_creates_remote_obligation_for_both(tmp_path):
    """The other timing: both objects received before triage -> both remote_erase."""
    db = ready(tmp_path)
    prepare(db, 'T', 'receiver-A', ['D', 'E'], '2099-01-01T00:00:00Z')
    early_e = cases()['e_before_freeze']
    receive(db, 'T', 'receiver-A', early_e['event_key'], early_e['receipts'], early_e['at'])
    early_d = cases()['both_after_early_receipt']
    view = receive(db, 'T', 'receiver-A', early_d['event_key'], early_d['receipts'], early_d['at'])
    assert view['state'] == 'accepted'
    assert item_states(view) == {'D': 'received', 'E': 'received'}

    result = triage(db, 'REQ', ['D', 'E'], '2099-01-01T00:00:00Z')
    assert obligations(result) == {'D': 'remote_erase', 'E': 'remote_erase'}
    rc = open_case(db, 'RC', 'REQ', 'T')
    assert {x['subject'] for x in rc['items']} == {'D', 'E'}


def test_receive_event_replay_is_idempotent_but_key_reuse_is_rejected(tmp_path):
    db = ready(tmp_path)
    prepare(db, 'T', 'receiver-A', ['D', 'E'], '2099-01-01T00:00:00Z')
    c = cases()
    first = receive(db, 'T', 'receiver-A', c['receive_d_only']['event_key'],
                    c['receive_d_only']['receipts'], c['receive_d_only']['at'])
    again = receive(db, 'T', 'receiver-A', c['receive_d_replay_equivalent']['event_key'],
                    c['receive_d_replay_equivalent']['receipts'],
                    c['receive_d_replay_equivalent']['at'])
    assert again == first
    d_rows = [r for r in receipt_rows(db, 'T') if r['subject'] == 'D']
    assert len(d_rows) == 1 and d_rows[0]['verdict'] == 'received'

    tampered = c['event_key_reused_with_other_content']
    with pytest.raises(ValueError, match='receive_event_identity_conflict'):
        receive(db, 'T', 'receiver-A', tampered['event_key'], tampered['receipts'], tampered['at'])
    # Reusing the same event key with a different object set is also a key conflict.
    with pytest.raises(ValueError, match='receive_event_identity_conflict'):
        receive(db, 'T', 'receiver-A', c['receive_d_only']['event_key'],
                c['receive_d_only']['receipts'] + [{'subject': 'E', 'sha256': E_HASH}],
                c['receive_d_only']['at'])
    # The original confirmation is untouched.
    d_rows = [r for r in receipt_rows(db, 'T') if r['subject'] == 'D']
    assert len(d_rows) == 1 and d_rows[0]['verdict'] == 'received'


def test_receive_after_expiry_is_rejected_but_evidence_is_kept(tmp_path):
    db = ready(tmp_path)
    prepare(db, 'T', 'receiver-A', ['D', 'E'], '2031-01-01T00:00:00Z')
    good = cases()['receive_d_only']
    receive(db, 'T', 'receiver-A', good['event_key'], good['receipts'], good['at'])
    late = receive(db, 'T', 'receiver-A', 'recv-E-after-expiry',
                   [{'subject': 'E', 'sha256': E_HASH}], '2031-06-01T00:00:00Z')
    assert item_states(late) == {'D': 'received', 'E': 'pending'}
    row = [r for r in receipt_rows(db, 'T') if r['event_key'] == 'recv-E-after-expiry'][0]
    assert row['verdict'] == 'rejected' and row['reason'] == 'transfer_expired'
    # D's earlier reception still answers as remote after the transfer lapsed.
    assert obligations(triage(db, 'REQ', ['D', 'E'], '2099-01-01T00:00:00Z')) == {
        'D': 'remote_erase', 'E': 'erase'}


def test_disputed_rejected_attempts_are_traceable_and_never_overwrite_received(tmp_path):
    db = ready(tmp_path)
    prepare(db, 'T', 'receiver-A', ['D', 'E'], '2099-01-01T00:00:00Z')
    c = cases()
    receive(db, 'T', 'receiver-A', c['receive_d_only']['event_key'],
            c['receive_d_only']['receipts'], c['receive_d_only']['at'])

    bad = c['bad_hash_e']
    view = receive(db, 'T', 'receiver-A', bad['event_key'], bad['receipts'], bad['at'])
    assert item_states(view) == {'D': 'received', 'E': 'disputed'}
    bad_row = [r for r in receipt_rows(db, 'T') if r['event_key'] == bad['event_key']][0]
    assert bad_row['verdict'] == 'disputed' and bad_row['reason'] == 'received_hash_mismatch'

    # A disputed object forces investigation inside the same request.
    assert obligations(triage(db, 'REQ', ['D', 'E'], '2099-01-01T00:00:00Z')) == {
        'D': 'remote_erase', 'E': 'investigate'}

    unknown = c['unknown_subject']
    view = receive(db, 'T', 'receiver-A', unknown['event_key'], unknown['receipts'], unknown['at'])
    outside = [r for r in view['other_receipts'] if r['event_key'] == unknown['event_key']]
    assert len(outside) == 1
    assert outside[0]['verdict'] == 'rejected'
    assert outside[0]['reason'] == 'subject_not_in_frozen_manifest'

    wrong = c['wrong_recipient_d']
    receive(db, 'T', wrong['recipient'], wrong['event_key'], wrong['receipts'], wrong['at'])
    row = [r for r in receipt_rows(db, 'T') if r['event_key'] == wrong['event_key']][0]
    assert row['verdict'] == 'rejected' and row['reason'] == 'recipient_mismatch'

    # The adjudication run moved: new receipts can no longer bind to the frozen run.
    evaluate(db)
    view = inspect(db, 'T')
    assert item_states(view) == {'D': 'received', 'E': 'disputed'}  # evidence preserved
    stale = receive(db, 'T', 'receiver-A', 'recv-after-rerun',
                    [{'subject': 'E', 'sha256': E_HASH}], '2030-05-01T00:00:00Z')
    row = [r for r in receipt_rows(db, 'T') if r['event_key'] == 'recv-after-rerun'][0]
    assert row['verdict'] == 'rejected' and row['reason'] == 'adjudication_run_changed'
    assert item_states(view) == {'D': 'received', 'E': 'disputed'}


def test_disputed_object_can_still_be_received_later_with_a_new_event(tmp_path):
    db = ready(tmp_path)
    prepare(db, 'T', 'receiver-A', ['D', 'E'], '2099-01-01T00:00:00Z')
    c = cases()
    bad = c['bad_hash_e']
    receive(db, 'T', 'receiver-A', bad['event_key'], bad['receipts'], bad['at'])
    good = c['e_before_freeze']
    view = receive(db, 'T', 'receiver-A', good['event_key'], good['receipts'], good['at'])
    assert item_states(view) == {'D': 'pending', 'E': 'received'}
    rows = [r for r in receipt_rows(db, 'T') if r['subject'] == 'E']
    assert [r['verdict'] for r in rows] == ['disputed', 'received']  # both facts retained


def test_expiry_never_erases_actual_receipt_evidence(tmp_path):
    db = ready(tmp_path)
    prepare(db, 'T', 'receiver-A', ['D', 'E'], '2099-01-01T00:00:00Z')
    c = cases()
    receive(db, 'T', 'receiver-A', c['receive_d_only']['event_key'],
            c['receive_d_only']['receipts'], c['receive_d_only']['at'])
    # An acknowledgement past expiry moves the whole transfer to 'expired'...
    view = acknowledge(db, 'T', 'receiver-A', {'D': D_HASH, 'E': E_HASH},
                       '2100-01-01T00:00:00Z')
    assert view['state'] == 'expired'
    # ...but D's reception evidence survives, and E was never received.
    assert item_states(view) == {'D': 'received', 'E': 'pending'}
    assert obligations(triage(db, 'REQ', ['D', 'E'], '2099-01-01T00:00:00Z')) == {
        'D': 'remote_erase', 'E': 'erase'}


def test_legacy_accepted_transfer_is_backfilled_from_frozen_manifest(tmp_path):
    db = ready(tmp_path)
    prepare(db, 'T', 'receiver-A', ['D', 'E'], '2099-01-01T00:00:00Z')
    # Simulate a database written by the pre-receipt build: accepted transfer,
    # no custody_receipt rows at all.
    con = connect(db)
    with con:
        con.execute("UPDATE custody_transfer SET state='accepted' WHERE id='T'")
        con.execute('DELETE FROM custody_receipt WHERE transfer_id=?', ('T',))
    con.close()

    view = inspect(db, 'T')
    assert item_states(view) == {'D': 'received', 'E': 'received'}
    rows = receipt_rows(db, 'T')
    assert {r['reason'] for r in rows} == {'legacy_accepted_transfer_backfill'}

    assert obligations(triage(db, 'REQ', ['D', 'E'], '2099-01-01T00:00:00Z')) == {
        'D': 'remote_erase', 'E': 'remote_erase'}
    rc = open_case(db, 'RC', 'REQ', 'T')
    assert {x['subject'] for x in rc['items']} == {'D', 'E'}

    # Backfill runs once; repeated inspection does not duplicate evidence.
    inspect(db, 'T')
    assert len(receipt_rows(db, 'T')) == 2


def test_rejected_late_receive_can_be_resolved_through_a_new_handoff(tmp_path):
    """Route A closure: post-freeze E receive is refused, but a new handoff can be
    prepared; the frozen request itself is never rewritten."""
    db = ready(tmp_path)
    prepare(db, 'T', 'receiver-A', ['D', 'E'], '2099-01-01T00:00:00Z')
    c = cases()
    receive(db, 'T', 'receiver-A', c['receive_d_only']['event_key'],
            c['receive_d_only']['receipts'], c['receive_d_only']['at'])
    triage(db, 'REQ', ['D', 'E'], '2099-01-01T00:00:00Z')
    late = c['late_e_valid']
    receive(db, 'T', 'receiver-A', late['event_key'], late['receipts'], late['at'])

    # A local erase duty (E) still blocks a replacement handoff for E itself...
    with pytest.raises(ValueError, match='pending_erasure_request'):
        prepare(db, 'T2', 'receiver-A', ['E'], '2099-02-01T00:00:00Z')
    # ...whereas D, whose frozen duty is remote_erase, can move in a new handoff.
    prepare(db, 'T2', 'receiver-A', ['D'], '2099-02-01T00:00:00Z')
    view = receive(db, 'T2', 'receiver-A', 'recv-d-again',
                   [{'subject': 'D', 'sha256': D_HASH}], '2030-03-02T00:00:00Z')
    assert item_states(view) == {'D': 'received'}

    # Two transfers now hold reception evidence for D -> ambiguous custody.
    assert obligations(triage(db, 'REQ2', ['D', 'E'], '2099-01-01T00:00:00Z')) == {
        'D': 'investigate', 'E': 'erase'}


def test_handoff_receive_and_inspect_cli(tmp_path, monkeypatch, capsys):
    import ast
    db = ready(tmp_path)
    prepare(db, 'T', 'receiver-A', ['D', 'E'], '2099-01-01T00:00:00Z')
    receipts_file = tmp_path / 'recv.json'
    c = cases()['receive_d_only']
    receipts_file.write_text(json.dumps(c['receipts']), encoding='utf-8')
    from retaincase.__main__ import main
    monkeypatch.setattr(sys, 'argv', [
        'retaincase', 'handoff-receive', '--db', str(db), '--id', 'T',
        '--recipient', 'receiver-A', '--event-key', c['event_key'],
        '--receipts', str(receipts_file), '--at', c['at']])
    main()
    out = ast.literal_eval(capsys.readouterr().out)
    assert out['receipt_state'] == 'partial'

    monkeypatch.setattr(sys, 'argv', [
        'retaincase', 'handoff-inspect', '--db', str(db), '--id', 'T'])
    main()
    out = ast.literal_eval(capsys.readouterr().out)
    assert {x['subject']: x['receipt_state'] for x in out['items']} == {
        'D': 'received', 'E': 'pending'}
