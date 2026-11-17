import json
from pathlib import Path

import pytest

from retaincase.ingest import initialize, load
from retaincase.report import export, verify
from retaincase.rules import action, evaluate, verify_decisions
from retaincase.store import connect

FIX = Path(__file__).resolve().parents[1] / 'fixtures'
CONFIG = FIX / 'jurisdiction-config.json'
EVENTS = FIX / 'jurisdiction-events.jsonl'


def base_config():
    return json.loads(CONFIG.read_text(encoding='utf-8'))


def base_events():
    return [json.loads(line) for line in EVENTS.read_text(encoding='utf-8').splitlines() if line.strip()]


def setup(tmp_path, config=None, events=None, name='j.db'):
    tmp_path.mkdir(parents=True, exist_ok=True)
    config_path = tmp_path / 'config.json'
    config_path.write_text(json.dumps(config if config is not None else base_config()),
                           encoding='utf-8')
    events_path = tmp_path / 'events.jsonl'
    events_path.write_text('\n'.join(json.dumps(e) for e in
                                     (events if events is not None else base_events())),
                           encoding='utf-8')
    db = tmp_path / name
    initialize(db, config_path)
    load(db, events_path)
    return db


def events_without(key):
    return [e for e in base_events() if e['event_key'] != key]


def without_succession_record():
    events = base_events()
    for event in events:
        if event['kind'] == 'jurisdiction_transfer':
            event.pop('succession')
    return events


def jurisdiction_rows(db, subject='D'):
    con = connect(db)
    run = con.execute('SELECT max(id) FROM run').fetchone()[0]
    rows = [dict(r) for r in con.execute(
        'SELECT * FROM jurisdiction_evidence WHERE run_id=? AND subject=? ORDER BY jurisdiction',
        (run, subject))]
    con.close()
    return rows


# --- the reference case -------------------------------------------------

def test_concurrent_contract_freezes_object_while_source_expiry_remains(tmp_path):
    db = setup(tmp_path)
    # J1: created 2025-06-15 + 365d = 2026-06-15 (not expired at 2026-06-01)
    # J2: terminated 2026-04-15 + 30d = 2026-05-15 (expired)
    assert evaluate(db, contract='concurrent', authority='memo-7') == {'D': '冻结'}
    assert evaluate(db, contract='single_successor', authority='memo-7') == {'D': '可销毁'}


def test_single_successor_requires_verifiable_succession_record(tmp_path):
    db = setup(tmp_path, events=without_succession_record())
    # The transfer is recorded but never says J1 liability passed to J2.
    assert evaluate(db, contract='single_successor', authority='memo-7') == {'D': '冻结'}
    assert evaluate(db, contract='concurrent', authority='memo-7') == {'D': '冻结'}


def test_single_successor_rejects_succession_with_missing_evidence(tmp_path):
    db = setup(tmp_path, events=events_without('succession-proof-7'))
    assert evaluate(db, contract='single_successor', authority='memo-7') == {'D': '证据不足'}
    rows = jurisdiction_rows(db)
    assert any(r['succession_basis'] is None or r['succession_event_key'] is None for r in rows
               if r['jurisdiction'] == 'J1')
    issues = {r[0] for r in connect(db).execute(
        "SELECT code FROM issue WHERE code='succession_unverified'")}
    assert issues == {'succession_unverified'}


def test_authority_is_mandatory_and_frozen_on_the_run(tmp_path):
    config = base_config()
    config.pop('jurisdiction_authority')
    db = setup(tmp_path, config=config)
    with pytest.raises(ValueError, match='jurisdiction_authority_required'):
        evaluate(db, contract='concurrent')
    with pytest.raises(ValueError, match='unknown_jurisdiction_contract'):
        evaluate(db, contract='last_row_wins', authority='memo-7')
    evaluate(db, contract='concurrent', authority='memo-7')
    con = connect(db)
    frozen = con.execute('SELECT * FROM run_jurisdiction ORDER BY run_id DESC LIMIT 1').fetchone()
    assert frozen['contract'] == 'concurrent' and frozen['authority'] == 'memo-7'
    assert json.loads(frozen['snapshot'])['contract'] == 'concurrent'
    con.close()


# --- start evidence belongs to one jurisdiction only --------------------

def test_j1_created_never_fills_j2_created_start(tmp_path):
    config = base_config()
    config['jurisdictions']['J2'] = {'id': 'J2-created', 'start': 'created', 'days': 30}
    db = setup(tmp_path, config=config)
    # J2 is the sole holder after succession but has no inception record of its
    # own; J1's created date must not be substituted for it.
    assert evaluate(db, contract='single_successor', authority='memo-7') == {'D': '证据不足'}
    rows = {r['jurisdiction']: r for r in jurisdiction_rows(db)}
    assert rows['J2']['applicability'] == 'applied'
    assert rows['J2']['start_event_id'] is None
    assert rows['J2']['evidence_gap'].startswith('start_evidence_gap:J2')
    assert rows['J1']['succession_event_key'] == 'j1-to-j2'
    # Under the concurrent contract J1 still has its own created start, while
    # J2's gap independently blocks erasure.
    assert evaluate(db, contract='concurrent', authority='memo-7') == {'D': '证据不足'}
    rows = {r['jurisdiction']: r for r in jurisdiction_rows(db)}
    assert rows['J1']['start_event_key'] == 'j1-origin'
    assert not rows['J1']['expired']
    assert rows['J2']['start_event_id'] is None


def test_j2_terminated_start_uses_only_j2_tagged_events(tmp_path):
    config = base_config()
    config['jurisdictions']['J2'] = {'id': 'J2-use', 'start': 'last_use', 'days': 30}
    events = base_events() + [
        # J1's later use is evidence of J1's clock only; J2's clock must use
        # J2's own last-use record.
        {'event_key': 'j1-use', 'subject': 'D', 'kind': 'use', 'jurisdiction': 'J1',
         'at': '2026-02-25'},
        {'event_key': 'j2-use', 'subject': 'D', 'kind': 'use', 'jurisdiction': 'J2',
         'at': '2026-04-01'},
    ]
    db = setup(tmp_path, config=config, events=events)
    assert evaluate(db, contract='single_successor', authority='memo-7') == {'D': '可销毁'}
    rows = {r['jurisdiction']: r for r in jurisdiction_rows(db)}
    assert rows['J2']['start_event_key'] == 'j2-use'
    assert rows['J2']['expires_on'] == '2026-05-01'


def test_tagged_event_outside_holder_interval_requires_review(tmp_path):
    config = base_config()
    config['jurisdictions']['J2'] = {'id': 'J2-use', 'start': 'last_use', 'days': 30}
    events = base_events() + [
        {'event_key': 'j1-use-after-transfer', 'subject': 'D', 'kind': 'use',
         'jurisdiction': 'J1', 'at': '2026-05-25'}]
    db = setup(tmp_path, config=config, events=events)
    assert evaluate(db, contract='single_successor', authority='memo-7') == {'D': '证据不足'}
    assert connect(db).execute("SELECT 1 FROM issue WHERE code='jurisdiction_conflict'").fetchone()


# --- attribution replay, overlaps and late events -----------------------

def test_as_of_before_transfer_keeps_source_jurisdiction(tmp_path):
    config = base_config()
    config['as_of'] = '2026-02-01'
    db = setup(tmp_path, config=config)
    evaluate(db, contract='single_successor', authority='memo-7')
    rows = {r['jurisdiction']: r for r in jurisdiction_rows(db)}
    assert rows['J1']['applicability'] == 'applied'
    assert 'J2' not in rows


def test_late_transfer_invalidates_earlier_run_without_rewriting_it(tmp_path):
    db = setup(tmp_path)
    assert evaluate(db, contract='concurrent', authority='memo-7') == {'D': '冻结'}
    con = connect(db)
    first = con.execute('SELECT max(id) FROM run').fetchone()[0]
    first_rows = [dict(r) for r in con.execute(
        'SELECT jurisdiction,applicability FROM jurisdiction_evidence WHERE run_id=?', (first,))]
    con.close()
    late = tmp_path / 'late.jsonl'
    late.write_text(json.dumps({'event_key': 'late-transfer', 'subject': 'D',
                                'kind': 'jurisdiction_transfer', 'from_jurisdiction': 'J2',
                                'to_jurisdiction': 'J1', 'at': '2025-01-01'}), encoding='utf-8')
    load(db, late)
    assert evaluate(db, contract='concurrent', authority='memo-7') == {'D': '证据不足'}
    con = connect(db)
    assert [dict(r) for r in con.execute(
        'SELECT jurisdiction,applicability FROM jurisdiction_evidence WHERE run_id=?', (first,))] == first_rows
    assert con.execute('SELECT count(*) FROM run').fetchone()[0] == 2
    con.close()


def test_overlapping_origins_require_review(tmp_path):
    events = base_events() + [
        {'event_key': 'j2-origin', 'subject': 'D', 'kind': 'jurisdiction_origin',
         'jurisdiction': 'J2', 'at': '2025-08-01'}]
    db = setup(tmp_path, events=events)
    assert evaluate(db, contract='concurrent', authority='memo-7') == {'D': '证据不足'}
    codes = {r[0] for r in connect(db).execute('SELECT code FROM issue')}
    assert 'jurisdiction_overlap' in codes


def test_transfer_from_unattributed_origin_is_unknown(tmp_path):
    events = [e for e in base_events() if e['event_key'] != 'j1-origin']
    db = setup(tmp_path, events=events)
    assert evaluate(db, contract='concurrent', authority='memo-7') == {'D': '证据不足'}
    codes = {r[0] for r in connect(db).execute('SELECT code FROM issue')}
    assert 'jurisdiction_conflict' in codes


def test_missing_attribution_is_unknown_not_guessed(tmp_path):
    events = [e for e in base_events()
              if e['kind'] not in ('jurisdiction_origin', 'jurisdiction_transfer')]
    db = setup(tmp_path, events=events)
    assert evaluate(db, contract='concurrent', authority='memo-7') == {'D': '证据不足'}
    assert connect(db).execute(
        "SELECT 1 FROM issue WHERE code='jurisdiction_unknown'").fetchone()


# --- policy versions ----------------------------------------------------

def test_policy_version_selected_by_effective_half_open_interval(tmp_path):
    config = base_config()
    config['jurisdictions']['J2'] = [
        {'id': 'J2-old', 'start': 'terminated', 'days': 365,
         'effective_from': '2020-01-01', 'effective_until': '2026-01-01'},
        {'id': 'J2-new', 'start': 'terminated', 'days': 30,
         'effective_from': '2026-01-01', 'effective_until': '2029-01-01'},
    ]
    db = setup(tmp_path, config=config)
    assert evaluate(db, contract='single_successor', authority='memo-7') == {'D': '可销毁'}
    rows = {r['jurisdiction']: r for r in jurisdiction_rows(db)}
    assert rows['J2']['policy_id'] == 'J2-new'


def test_policy_version_gap_is_a_review_state(tmp_path):
    config = base_config()
    config['jurisdictions']['J2'] = {'id': 'J2-only', 'start': 'terminated', 'days': 30,
                                     'effective_from': '2027-01-01'}
    db = setup(tmp_path, config=config)
    assert evaluate(db, contract='single_successor', authority='memo-7') == {'D': '证据不足'}
    assert connect(db).execute(
        "SELECT 1 FROM issue WHERE code LIKE 'jurisdiction_policy_gap:%'").fetchone()


def test_policy_version_overlap_is_a_review_state(tmp_path):
    config = base_config()
    config['jurisdictions']['J2'] = [
        {'id': 'J2-a', 'start': 'terminated', 'days': 30, 'effective_from': '2025-01-01'},
        {'id': 'J2-b', 'start': 'terminated', 'days': 90, 'effective_from': '2026-01-01'},
    ]
    db = setup(tmp_path, config=config)
    assert evaluate(db, contract='single_successor', authority='memo-7') == {'D': '证据不足'}
    assert connect(db).execute(
        "SELECT 1 FROM issue WHERE code LIKE 'jurisdiction_policy_overlap:%'").fetchone()


# --- holds and dependencies survive jurisdiction changes ----------------

def test_legal_hold_is_not_released_by_transfer(tmp_path):
    events = base_events() + [
        {'event_key': 'court-hold', 'subject': 'D', 'kind': 'hold_start',
         'hold_id': 'court-9', 'at': '2026-05-20'}]
    db = setup(tmp_path, events=events)
    for contract in ('concurrent', 'single_successor'):
        assert evaluate(db, contract=contract, authority='memo-7') == {'D': '冻结'}
        assert connect(db).execute(
            "SELECT 1 FROM issue WHERE code='legal_hold' AND run_id=(SELECT max(id) FROM run)").fetchone()


def test_hold_scope_tag_crosses_jurisdiction_attribution(tmp_path):
    config = base_config()
    config['subjects']['D']['tags'] = ['regulated']
    config['subjects']['O'] = {'path': 'O.bin'}
    events = base_events() + [
        {'event_key': 'o-origin', 'subject': 'O', 'kind': 'jurisdiction_origin',
         'jurisdiction': 'J2', 'at': '2025-01-01'},
        {'event_key': 'scoped-hold', 'subject': 'O', 'kind': 'hold_start',
         'scope_tag': 'regulated', 'hold_id': 'court-tag', 'at': '2026-05-20'}]
    db = setup(tmp_path, config=config, events=events)
    result = evaluate(db, contract='concurrent', authority='memo-7')
    assert result['D'] == '冻结'
    con = connect(db)
    hold = con.execute("SELECT id FROM raw_event WHERE event_key='scoped-hold'").fetchone()[0]
    linked = {r[0] for r in con.execute(
        "SELECT event_id FROM evidence WHERE subject='D' AND event_id IS NOT NULL "
        "AND run_id=(SELECT max(id) FROM run)")}
    assert hold in linked
    con.close()


def test_dependency_closure_survives_jurisdiction_decision(tmp_path):
    config = base_config()
    config['subjects']['E'] = {'path': 'E.bin'}
    config['jurisdictions']['J2'] = {'id': 'J2-policy-2025', 'start': 'terminated', 'days': 1}
    events = base_events() + [
        {'event_key': 'd-dep', 'subject': 'E', 'kind': 'depends_on', 'parent': 'D',
         'at': '2026-05-01'},
        {'event_key': 'e-origin', 'subject': 'E', 'kind': 'jurisdiction_origin',
         'jurisdiction': 'J2', 'at': '2025-01-01'},
        {'event_key': 'e-terminate', 'subject': 'E', 'kind': 'terminate',
         'at': '2026-06-01'}]
    db = setup(tmp_path, config=config, events=events)
    result = evaluate(db, contract='single_successor', authority='memo-7')
    # D's J2 clock has expired, but its dependent E is still retained, so the
    # closure freezes D.
    assert result['D'] == '冻结' and result['E'] == '冻结'
    con = connect(db)
    assert con.execute(
        "SELECT 1 FROM issue WHERE subject='D' AND code='dependent_retained'"
    ).fetchone()
    con.close()


def test_retained_descendant_source_evidence_reaches_transferred_parent(tmp_path):
    config = base_config()
    config['subjects']['E'] = {'path': 'E.bin'}
    config['jurisdictions']['J1'] = {'id': 'J1-policy-2024', 'start': 'created', 'days': 3650}
    events = base_events() + [
        {'event_key': 'e-origin', 'subject': 'E', 'kind': 'jurisdiction_origin',
         'jurisdiction': 'J1', 'at': '2025-01-01'},
        {'event_key': 'd-dep', 'subject': 'E', 'kind': 'depends_on', 'parent': 'D',
         'at': '2026-05-01'}]
    db = setup(tmp_path, config=config, events=events)
    result = evaluate(db, contract='single_successor', authority='memo-7')
    assert result['D'] == '冻结' and result['E'] == '冻结'
    con = connect(db)
    linked = {r[0] for r in con.execute(
        "SELECT event_id FROM evidence WHERE subject='D' AND event_id IS NOT NULL")}
    dep_id = con.execute("SELECT id FROM raw_event WHERE event_key='d-dep'").fetchone()[0]
    assert dep_id in linked


# --- contract is frozen, not a per-rule switch ---------------------------

def test_contract_change_creates_new_run_and_keeps_old_decisions(tmp_path):
    db = setup(tmp_path)
    assert evaluate(db, contract='concurrent', authority='memo-7') == {'D': '冻结'}
    assert evaluate(db, contract='single_successor', authority='memo-7') == {'D': '可销毁'}
    con = connect(db)
    runs = con.execute('SELECT id FROM run ORDER BY id').fetchall()
    assert len(runs) == 2
    old = [dict(r) for r in con.execute(
        'SELECT contract FROM run_jurisdiction WHERE run_id=?', (runs[0][0],))]
    assert old == [{'contract': 'concurrent'}]
    assert con.execute('SELECT count(*) FROM decision WHERE run_id=?', (runs[0][0],)).fetchone()[0] == 1
    con.close()


def test_verify_detects_contract_snapshot_tamper(tmp_path):
    db = setup(tmp_path)
    evaluate(db, contract='single_successor', authority='memo-7')
    assert verify(db) == []
    con = connect(db)
    con.execute("UPDATE run_jurisdiction SET snapshot='{}'")
    con.commit()
    con.close()
    assert any(x.startswith('run_jurisdiction:') for x in verify(db))


def test_verify_detects_policy_digest_tamper(tmp_path):
    db = setup(tmp_path)
    evaluate(db, contract='concurrent', authority='memo-7')
    con = connect(db)
    con.execute("UPDATE jurisdiction_evidence SET policy_digest='deadbeef'")
    con.commit()
    con.close()
    assert any(x.startswith('jurisdiction_policy:') for x in verify(db))


def test_verify_decisions_recomputes_frozen_contract(tmp_path):
    db = setup(tmp_path)
    evaluate(db, contract='single_successor', authority='memo-7')
    assert verify_decisions(db) == []
    con = connect(db)
    con.execute("UPDATE decision SET status='冻结' WHERE subject='D'")
    con.commit()
    con.close()
    assert 'decision_mismatch:D' in verify_decisions(db)


# --- report ------------------------------------------------------------

def test_report_shows_start_policy_succession_and_exclusion(tmp_path):
    db = setup(tmp_path)
    evaluate(db, contract='single_successor', authority='memo-7')
    out = export(db, tmp_path / 'report.json')
    data = json.loads(out.read_text(encoding='utf-8'))
    assert data['contract']['contract'] == 'single_successor'
    rows = {r['jurisdiction']: r for r in data['jurisdictions']['D']}
    assert rows['J1']['applicability'] == 'excluded'
    assert rows['J1']['succession']['basis'] == 'synthetic-escrow-agreement-7'
    assert rows['J1']['exclusion_basis'] == 'succession_assumed'
    assert rows['J1']['policy']['body']['start'] == 'created'
    assert rows['J2']['start']['event_key'] == 'j2-terminate'
    assert rows['J2']['policy']['id'] == 'J2-policy-2025'
    text = out.with_suffix('.md').read_text(encoding='utf-8')
    assert 'J1 [excluded]' in text and '承接证明' in text


def test_report_of_old_run_ignores_new_transfer_event(tmp_path):
    db = setup(tmp_path)
    evaluate(db, contract='concurrent', authority='memo-7')
    first = export(db, tmp_path / 'first.json')
    first_text = first.with_suffix('.md').read_text(encoding='utf-8')
    late = tmp_path / 'late.jsonl'
    late.write_text(json.dumps({'event_key': 'late-transfer', 'subject': 'D',
                                'kind': 'jurisdiction_transfer', 'from_jurisdiction': 'J2',
                                'to_jurisdiction': 'J1', 'at': '2025-01-01'}), encoding='utf-8')
    load(db, late)
    evaluate(db, contract='concurrent', authority='memo-7')
    again = export(db, tmp_path / 'second.json')
    assert json.loads(again.read_text())['run']['id'] != json.loads(first.read_text())['run']['id']
    old = [d for d in json.loads(first.read_text())['decisions']]
    assert old[0]['status'] == '冻结'
    assert first_text != again.with_suffix('.md').read_text(encoding='utf-8')


# --- execution stays tied to the frozen adjudication ---------------------

def test_plan_only_destroys_objects_allowed_by_frozen_contract(tmp_path):
    db = setup(tmp_path)
    evaluate(db, contract='concurrent', authority='memo-7')
    plan = tmp_path / 'plan.json'
    action('plan', db, out=plan)
    assert json.loads(plan.read_text()) == []
    revision = base_config()
    revision['rule_version'] = 'jv2'
    revision_path = tmp_path / 'jv2.json'
    revision_path.write_text(json.dumps(revision), encoding='utf-8')
    action('recheck', db, out=revision_path, contract='single_successor', authority='memo-7')
    action('plan', db, out=plan)
    assert [x['subject'] for x in json.loads(plan.read_text())] == ['D']
    root = tmp_path / 'sandbox'
    root.mkdir()
    (root / 'D.bin').write_bytes(b'demo')
    assert action('execute', db, sandbox=root, out=plan) == ['D']


def test_attribution_source_conflict_changes_the_decision(tmp_path):
    db = setup(tmp_path)
    assert evaluate(db, contract='single_successor', authority='memo-7') == {'D': '可销毁'}
    # A second source claims a different jurisdiction for the same transfer
    # event key.  The system must not pick the last imported row; the object
    # becomes pending review.
    conflicting = tmp_path / 'conflict.jsonl'
    conflicting.write_text(json.dumps(
        {'event_key': 'j1-to-j2', 'subject': 'D', 'kind': 'jurisdiction_transfer',
         'from_jurisdiction': 'J1', 'to_jurisdiction': 'J3',
         'succession': {'basis': 'other-basis', 'evidence': 'succession-proof-7'},
         'at': '2026-03-01'}), encoding='utf-8')
    assert load(db, conflicting) == 0
    assert evaluate(db, contract='single_successor', authority='memo-7') == {'D': '证据不足'}
    con = connect(db)
    assert con.execute("SELECT 1 FROM issue WHERE code='identity_conflict' AND subject='D'").fetchone()
    # The conflicting row never became a raw_event.
    assert con.execute("SELECT count(*) FROM raw_event WHERE event_key='j1-to-j2'").fetchone()[0] == 1
    con.close()


def test_late_origin_event_reopens_closed_holder_conflict(tmp_path):
    db = setup(tmp_path)
    assert evaluate(db, contract='single_successor', authority='memo-7') == {'D': '可销毁'}
    late = tmp_path / 'late-origin.jsonl'
    late.write_text(json.dumps(
        {'event_key': 'j1-reorigin', 'subject': 'D', 'kind': 'jurisdiction_origin',
         'jurisdiction': 'J1', 'at': '2026-04-01'}), encoding='utf-8')
    load(db, late)
    # J1's interval closed at the 2026-03-01 transfer; a new inception with no
    # transfer back is contradictory and blocks a final disposition.
    assert evaluate(db, contract='single_successor', authority='memo-7') == {'D': '证据不足'}
    assert connect(db).execute(
        "SELECT 1 FROM issue WHERE code='jurisdiction_conflict'").fetchone()


def test_hold_release_still_needs_its_own_start(tmp_path):
    events = base_events() + [
        {'event_key': 'hold-start', 'subject': 'D', 'kind': 'hold_start',
         'hold_id': 'court-4', 'at': '2026-04-01'},
        {'event_key': 'hold-release', 'subject': 'D', 'kind': 'hold_end',
         'hold_id': 'court-4', 'at': '2026-05-01'}]
    db = setup(tmp_path, events=events)
    # Released hold no longer freezes, and the frozen-contract decision stands.
    assert evaluate(db, contract='single_successor', authority='memo-7') == {'D': '可销毁'}
    broken = setup(tmp_path / 'broken', events=events + [
        {'event_key': 'stray-release', 'subject': 'D', 'kind': 'hold_end',
         'hold_id': 'never-started', 'at': '2026-05-02'}])
    assert evaluate(broken, contract='single_successor', authority='memo-7') == {'D': '证据不足'}


def test_jurisdiction_without_any_policy_version_is_unknown(tmp_path):
    config = base_config()
    config['jurisdictions'].pop('J1')
    db = setup(tmp_path, config=config)
    assert evaluate(db, contract='concurrent', authority='memo-7') == {'D': '证据不足'}
    assert connect(db).execute(
        "SELECT 1 FROM issue WHERE code LIKE 'jurisdiction_policy_gap:J1'").fetchone()
