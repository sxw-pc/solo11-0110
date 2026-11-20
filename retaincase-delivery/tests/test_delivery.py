"""Offline tests for minimized analytic delivery and cross-package intersection control."""
import copy
import json
from pathlib import Path

import pytest

from retaincase.ingest import initialize, load
from retaincase.rules import evaluate
from retaincase.minimization import register
from retaincase.requests import freeze_delivery, resume_delivery, verify_delivery, delivery_report
from retaincase.store import connect

FIX = Path(__file__).resolve().parents[1] / 'fixtures' / 'delivery'
CSV = FIX / 'minimization-inventory.csv'
SPECS = FIX / 'specs'


def load_spec(name):
    spec = json.loads((SPECS / name).read_text(encoding='utf-8'))
    spec['inventory_csv_path'] = str(CSV)
    return spec


def ready(tmp_path):
    db = tmp_path / 'ledger.db'
    initialize(db, FIX / 'config.json')
    load(db, FIX / 'events.jsonl')
    decisions = evaluate(db)
    register(db, 'inv-1', CSV)
    return db, decisions


def package_dir(tmp_path):
    root = tmp_path / 'packages'
    root.mkdir()
    return root


def read_package(root, request_id, name='package.json'):
    return json.loads((root / request_id / name).read_text(encoding='utf-8'))


# --------------------------------------------------------------------------- #
# Counterexample: hold_new and coarsen_new
# --------------------------------------------------------------------------- #

def test_hold_new_suspends_cross_package_singleton_intersections(tmp_path):
    db, decisions = ready(tmp_path)
    assert decisions == {'A': '冻结', 'B': '冻结', 'C': '可销毁', 'D': '可销毁',
                         'E': '可销毁', 'F': '冻结', 'G': '可销毁'}
    root = package_dir(tmp_path)
    first = freeze_delivery(db, 'REQ-OLD', 'inv-1', 'analyst-east', 'trend-analysis',
                            'hold_new', load_spec('counterexample-old.json'), root)
    assert first['state'] == 'published'
    second = freeze_delivery(db, 'REQ-HOLD', 'inv-1', 'analyst-east', 'trend-analysis',
                             'hold_new', load_spec('counterexample-new.json'), root)
    # Both packages individually satisfy k=2, but every intersection is a singleton.
    assert second['state'] == 'held'
    assert second['hold_reason'] == 'intersection_below_k'
    assert not (root / 'REQ-HOLD').exists()
    assert not list(root.glob('.staging-*'))


def test_coarsen_new_publishes_coarser_package_and_records_protected_intersections(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    freeze_delivery(db, 'REQ-OLD', 'inv-1', 'analyst-east', 'trend-analysis',
                    'coarsen_new', load_spec('counterexample-old.json'), root)
    result = freeze_delivery(db, 'REQ-COARSE', 'inv-1', 'analyst-east', 'trend-analysis',
                             'coarsen_new', load_spec('counterexample-new.json'), root)
    assert result['state'] == 'published'
    package = read_package(root, 'REQ-COARSE')
    # All six old subjects collapse into one generalized age band.
    assert len(package['rows']) == 6
    assert {row['age_band'] for row in package['rows']} == {'*'}
    proof = read_package(root, 'REQ-COARSE', 'proof.json')
    protected = proof['protected_intersections']
    assert protected and all(x['overlap_count'] == 1 and x['protected'] for x in protected)
    check = verify_delivery(db, 'REQ-COARSE', root)
    assert check['problems'] == [] and check['state'] == 'published'
    report = delivery_report(db, 'REQ-COARSE')
    # The report never reveals which subject belongs to which anonymous group: only overlap
    # counts and anonymous class numbers are emitted, no internal subject identifiers.
    import re
    blob = json.dumps(report, ensure_ascii=False)
    for subject in 'ABCDEG':
        assert not re.search(r'(?<![A-Za-z0-9_-])' + subject + r'(?![A-Za-z0-9_-])', blob)
    assert all('overlap_count' in x for x in report['intersections'])


def test_no_feasible_generalization_suspends_without_half_package(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    freeze_delivery(db, 'REQ-OLD', 'inv-1', 'analyst-east', 'trend-analysis',
                    'hold_new', load_spec('counterexample-old.json'), root)
    result = freeze_delivery(db, 'REQ-NF', 'inv-1', 'analyst-east', 'trend-analysis',
                             'coarsen_new', load_spec('no-feasible-new.json'), root)
    assert result['state'] == 'held'
    assert result['hold_reason'] == 'no_feasible_coarsening'
    assert not (root / 'REQ-NF').exists()
    assert not list(root.glob('.staging-*'))


# --------------------------------------------------------------------------- #
# Suppression boundary and reappearing subjects
# --------------------------------------------------------------------------- #

def test_suppression_isolates_whole_rows_within_budget(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    result = freeze_delivery(db, 'REQ-SUP', 'inv-1', 'analyst-east', 'geo-analysis',
                             'hold_new', load_spec('suppression-old.json'), root)
    assert result['state'] == 'published'
    package = read_package(root, 'REQ-SUP')
    # city-alpha={A,C}, city-beta={B,G}, gamma={D}, delta={E}: the two singletons are suppressed.
    assert package['suppressed_count'] == 2
    published_subjects_pseudo = {r['pseudonym'] for r in package['rows']}
    assert len(published_subjects_pseudo) == 4
    proof = read_package(root, 'REQ-SUP', 'proof.json')
    assert sorted(proof['suppressed_subjects']) == ['D', 'E']


def test_suppression_budget_exceeded_suspends_package(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    spec = load_spec('suppression-old.json')
    spec['max_suppression'] = 1
    result = freeze_delivery(db, 'REQ-SUP2', 'inv-1', 'analyst-east', 'geo-analysis',
                             'hold_new', spec, root)
    assert result['state'] == 'held'
    assert result['hold_reason'] == 'suppression_budget_exceeded'
    assert not (root / 'REQ-SUP2').exists()


def test_reappearing_suppressed_subject_is_not_treated_as_linkable_category(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    freeze_delivery(db, 'REQ-SUP', 'inv-1', 'analyst-east', 'geo-analysis',
                    'hold_new', load_spec('suppression-old.json'), root)
    # D and E were suppressed in the old package; the new region proposal reintroduces them.
    result = freeze_delivery(db, 'REQ-RE', 'inv-1', 'analyst-east', 'geo-analysis',
                             'hold_new', load_spec('reappear-new.json'), root)
    assert result['state'] == 'published'
    package = read_package(root, 'REQ-RE')
    # D and E were absent from every observable old class. In the new package r1={A,B,C,G}
    # satisfies k locally and against old observable classes; r2={E} fails local k only and is
    # suppressed within max_suppression=1. Absence is never treated as a linkable category.
    assert package['suppressed_count'] == 1
    proof = read_package(root, 'REQ-RE', 'proof.json')
    assert proof['suppressed_subjects'] == ['E']
    assert all(entry['overlap_count'] >= 2 for entry in proof['intersections'])


# --------------------------------------------------------------------------- #
# Third package accumulation
# --------------------------------------------------------------------------- #

def test_third_package_accumulates_cross_intersections(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    old = load_spec('counterexample-old.json')
    freeze_delivery(db, 'REQ-P1', 'inv-1', 'analyst-east', 'trend-analysis',
                    'coarsen_new', old, root)
    # Second package is safe alone: age bands {A,C,E} and {B,D,G}.
    spec2 = load_spec('counterexample-new.json')
    spec2['max_suppression'] = 2
    freeze_delivery(db, 'REQ-P2', 'inv-1', 'analyst-east', 'trend-analysis',
                    'coarsen_new', spec2, root)
    # A third package whose class splits P1/P2 overlaps down to singletons must be held even
    # though each earlier package was independently safe.
    third = copy.deepcopy(spec2)
    third['quasi_identifiers'] = ['zone', 'age_band']
    third['base_levels'] = {'zone': 0, 'age_band': 0}
    third['lattice'] = {
        'zone': [{'name': 'zone-exact', 'cost': 0},
                 {'name': 'zone-top', 'cost': 9, 'buckets': {'z1': '*', 'z2': '*', 'z3': '*'}}],
        'age_band': [{'name': 'age-exact', 'cost': 0},
                     {'name': 'age-top', 'cost': 9, 'buckets': {'a2': '*', 'a3': '*'}}],
    }
    held = freeze_delivery(db, 'REQ-P3', 'inv-1', 'analyst-east', 'trend-analysis',
                           'hold_new', third, root)
    assert held['state'] == 'held'
    coarsened = freeze_delivery(db, 'REQ-P3C', 'inv-1', 'analyst-east', 'trend-analysis',
                                'coarsen_new', third, root)
    assert coarsened['state'] == 'published'
    package = read_package(root, 'REQ-P3C')
    assert all(row['zone'] == '*' or row['age_band'] == '*' for row in package['rows'])


# --------------------------------------------------------------------------- #
# Field provenance leaks
# --------------------------------------------------------------------------- #

def test_direct_field_can_never_be_delivered(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    spec = load_spec('counterexample-old.json')
    spec['deliverable_fields'] = ['zone', 'ssn']
    with pytest.raises(ValueError, match='direct_field_forbidden:ssn'):
        freeze_delivery(db, 'REQ-DIRECT', 'inv-1', 'analyst-east', 'x', 'hold_new', spec, root)


def test_reversible_derived_from_direct_is_rejected_including_transitive(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    spec = load_spec('counterexample-old.json')
    spec['deliverable_fields'] = ['zone', 'reverse_token']
    spec['lineage'] = {'reverse_token': {'inputs': ['ssn'], 'reversible': True}}
    with pytest.raises(ValueError, match='derived_reversible_direct:reverse_token'):
        freeze_delivery(db, 'REQ-REV', 'inv-1', 'analyst-east', 'x', 'hold_new', spec, root)
    # Transitive chain: contact <- contact_seed <- ssn, every link reversible.
    spec['deliverable_fields'] = ['zone', 'contact']
    spec['lineage'] = {
        'contact': {'inputs': ['contact_seed'], 'reversible': True},
        'contact_seed': {'inputs': ['ssn'], 'reversible': True},
    }
    with pytest.raises(ValueError, match='derived_reversible_direct:contact'):
        freeze_delivery(db, 'REQ-REV2', 'inv-1', 'analyst-east', 'x', 'hold_new', spec, root)


def test_missing_lineage_relation_freezes_request_as_held_unverified(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    spec = load_spec('counterexample-old.json')
    spec['deliverable_fields'] = ['zone', 'contact']
    spec['lineage'] = {}
    result = freeze_delivery(db, 'REQ-UNV', 'inv-1', 'analyst-east', 'x',
                             'hold_new', spec, root)
    assert result['state'] == 'held'
    assert result['hold_reason'] == 'lineage_unverified:contact'
    assert not (root / 'REQ-UNV').exists()


def test_irreversible_derived_is_published_with_lineage_proof(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    spec = load_spec('counterexample-old.json')
    spec['deliverable_fields'] = ['zone', 'contact']
    spec['lineage'] = {'contact': {'inputs': ['score'], 'reversible': False}}
    result = freeze_delivery(db, 'REQ-OK', 'inv-1', 'analyst-east', 'x',
                             'hold_new', spec, root)
    assert result['state'] == 'published'
    proof = read_package(root, 'REQ-OK', 'proof.json')
    assert proof['lineage']['contact'] == [{'input': 'score', 'reversible': False}]


# --------------------------------------------------------------------------- #
# Decision change, destroyed and uncertain subjects, legal-hold participation
# --------------------------------------------------------------------------- #

def test_uncertain_and_destroyed_subjects_are_excluded(tmp_path):
    db, decisions = ready(tmp_path)
    root = package_dir(tmp_path)
    # Mark F evidence-insufficient in a new run without deleting evidence rows (FK protected).
    con = connect(db)
    cfg = json.loads(con.execute('SELECT config_raw FROM batch').fetchone()[0])
    cfg['policy']['active']['start'] = 'terminated'
    con.execute('UPDATE batch SET config_raw=?', (json.dumps(cfg).encode(),))
    con.commit()
    con.close()
    new_decisions = evaluate(db)
    assert new_decisions['F'] == '证据不足'
    result = freeze_delivery(db, 'REQ-GATE', 'inv-1', 'analyst-east', 'x',
                             'hold_new', load_spec('counterexample-old.json'), root)
    assert result['state'] == 'published'
    pseudo_rows = read_package(root, 'REQ-GATE')['rows']
    pseudonyms = {r['pseudonym'] for r in pseudo_rows}
    ledger = connect(db)
    f_pseudo = ledger.execute(
        "SELECT pseudonym FROM delivery_pseudo WHERE request_id='REQ-GATE' AND subject='F'").fetchone()
    ledger.close()
    assert f_pseudo is None
    assert all(p in pseudonyms for p in pseudonyms) and len(pseudo_rows) == 6  # F excluded


def test_destroyed_subject_cannot_be_reexported_from_old_inventory(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    con = connect(db)
    run = con.execute('SELECT max(id) FROM run').fetchone()[0]
    with con:
        con.execute("INSERT INTO execution(run_id,subject,action,before_hash,after_state) "
                    "VALUES (?,?,?,?,?)", (run, 'D', 'destroy', 'h', 'absent'))
    con.close()
    freeze_delivery(db, 'REQ-DEST', 'inv-1', 'analyst-east', 'x',
                    'hold_new', load_spec('gate.json'), root)
    package = read_package(root, 'REQ-DEST')
    ledger = connect(db)
    members = [r['subject'] for r in ledger.execute(
        "SELECT subject FROM delivery_pseudo WHERE request_id='REQ-DEST' ORDER BY subject")]
    ledger.close()
    assert 'D' not in members
    # z2 becomes a singleton (C alone) after D is removed, so that whole row is suppressed and
    # four subjects in the z1/z3 classes remain.
    assert len(package['rows']) == 4


def test_legal_hold_subject_participates_but_evidence_is_untouched(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    before = connect(db).execute(
        "SELECT count(*) FROM evidence WHERE subject='B'").fetchone()[0]
    result = freeze_delivery(db, 'REQ-HOLD-B', 'inv-1', 'analyst-east', 'x',
                             'hold_new', load_spec('counterexample-old.json'), root)
    assert result['state'] == 'published'
    con = connect(db)
    after = con.execute("SELECT count(*) FROM evidence WHERE subject='B'").fetchone()[0]
    status = con.execute("SELECT status FROM decision WHERE subject='B' AND run_id="
                         "(SELECT max(id) FROM run)").fetchone()[0]
    con.close()
    assert after == before and status == '冻结'


def test_publish_rechecks_latest_run_and_holds_stale_frozen_request(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    # Freeze two feasible packages, then advance the run; replay must not publish against a
    # stale run even when the request itself would be safe at base granularity.
    first = freeze_delivery(db, 'REQ-S1', 'inv-1', 'analyst-north', 'a',
                            'hold_new', load_spec('counterexample-old.json'), root)
    assert first['state'] == 'published'
    second = freeze_delivery(db, 'REQ-STALE', 'inv-1', 'analyst-south', 'b',
                             'hold_new', load_spec('suppression-old.json'), root)
    assert second['state'] == 'published'
    evaluate(db)  # newer run invalidates every frozen request
    held = resume_delivery(db, 'REQ-STALE', root)
    assert held['state'] == 'held' and held['hold_reason'] == 'decision_run_stale'
    row = connect(db).execute(
        "SELECT state,hold_reason FROM delivery_request WHERE request_id='REQ-STALE'").fetchone()
    assert row['state'] == 'held' and row['hold_reason'] == 'decision_run_stale'


# --------------------------------------------------------------------------- #
# Identity, interruption recovery, tamper verification
# --------------------------------------------------------------------------- #

def test_request_identity_conflict_and_idempotent_resume(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    spec = load_spec('counterexample-old.json')
    first = freeze_delivery(db, 'REQ-IDEM', 'inv-1', 'analyst-east', 'x', 'hold_new', spec, root)
    again = freeze_delivery(db, 'REQ-IDEM', 'inv-1', 'analyst-east', 'x', 'hold_new', spec, root)
    # inspect() appends the frozen pseudonym map; the delivery receipt itself is identical.
    assert {k: v for k, v in again.items() if k != 'pseudonyms'} == \
        {k: v for k, v in first.items() if k != 'pseudonyms'}
    assert again['pseudonyms'] == first['pseudonyms']
    changed = copy.deepcopy(spec)
    changed['purpose'] = 'different-purpose'
    with pytest.raises(ValueError, match='request_identity_conflict'):
        freeze_delivery(db, 'REQ-IDEM', 'inv-1', 'analyst-east', 'different-purpose',
                        'hold_new', spec, root)


def test_interrupted_write_is_rebuilt_without_half_package(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    result = freeze_delivery(db, 'REQ-CRASH', 'inv-1', 'analyst-east', 'x',
                             'hold_new', load_spec('counterexample-old.json'), root)
    target = root / 'REQ-CRASH'
    # Simulate a crash that removed the finished directory, plus a stale staging tree.
    import shutil
    shutil.move(str(target), str(root / '.staging-REQ-CRASH'))
    resumed = resume_delivery(db, 'REQ-CRASH', root)
    assert resumed['state'] == 'published'
    assert (root / 'REQ-CRASH' / 'package.json').is_file()
    assert not (root / '.staging-REQ-CRASH').exists()
    rebuilt = read_package(root, 'REQ-CRASH')
    assert result['package_hash'] == hashlib_of(root / 'REQ-CRASH' / 'package.json')
    assert rebuilt['request_id'] == 'REQ-CRASH'


def hashlib_of(path):
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_tampered_package_or_proof_revokes_only_that_request(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    freeze_delivery(db, 'REQ-T1', 'inv-1', 'analyst-east', 'x',
                    'hold_new', load_spec('counterexample-old.json'), root)
    freeze_delivery(db, 'REQ-T2', 'inv-1', 'analyst-east', 'y',
                    'hold_new', load_spec('counterexample-old.json'), root)
    tampered = root / 'REQ-T1' / 'package.json'
    data = json.loads(tampered.read_text(encoding='utf-8'))
    data['rows'][0]['score'] = 'tampered'
    tampered.write_text(json.dumps(data), encoding='utf-8')
    verdict = verify_delivery(db, 'REQ-T1', root)
    assert verdict['state'] == 'revoked'
    assert any(x.startswith('package_tampered') for x in verdict['problems'])
    other = verify_delivery(db, 'REQ-T2', root)
    assert other['state'] == 'published' and other['problems'] == []
    # The legal package directory is never rewritten by verification.
    assert (root / 'REQ-T2' / 'package.json').is_file()


def test_proof_tamper_revokes_and_proof_contains_internal_identifiers_not_package(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    freeze_delivery(db, 'REQ-P', 'inv-1', 'analyst-east', 'x',
                    'hold_new', load_spec('counterexample-old.json'), root)
    package_blob = (root / 'REQ-P' / 'package.json').read_text(encoding='utf-8')
    assert 'subject' not in package_blob
    proof = root / 'REQ-P' / 'proof.json'
    data = json.loads(proof.read_text(encoding='utf-8'))
    data['classes'][0]['members'] = ['FORGED']
    proof.write_text(json.dumps(data), encoding='utf-8')
    verdict = verify_delivery(db, 'REQ-P', root)
    assert verdict['state'] == 'revoked'
    assert 'package_tampered:proof.json' in verdict['problems']


def test_tampered_class_splitting_is_caught_without_self_intersection_masking(tmp_path):
    """The cross check excludes the request under verification so self-intersection cannot mask."""
    from retaincase import delivery
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    freeze_delivery(db, 'REQ-OLD', 'inv-1', 'analyst-east', 'trend-analysis',
                    'coarsen_new', load_spec('counterexample-old.json'), root)
    freeze_delivery(db, 'REQ-NEW', 'inv-1', 'analyst-east', 'trend-analysis',
                    'coarsen_new', load_spec('counterexample-new.json'), root)
    con = connect(db)
    inclusive = delivery._prior_classes(con, 'analyst-east')
    exclusive = delivery._prior_classes(con, 'analyst-east', exclude_request='REQ-NEW')
    con.close()
    assert {pid for pid, _ in inclusive} == {'REQ-OLD', 'REQ-NEW'}
    assert {pid for pid, _ in exclusive} == {'REQ-OLD'}
    # Forging the proof still revokes via the hash gate before any class math runs.
    proof = root / 'REQ-NEW' / 'proof.json'
    data = json.loads(proof.read_text(encoding='utf-8'))
    data['classes'][0]['members'] = data['classes'][0]['members'][:1]
    proof.write_text(json.dumps(data), encoding='utf-8')
    verdict = verify_delivery(db, 'REQ-NEW', root)
    assert verdict['state'] == 'revoked'
    assert 'package_tampered:proof.json' in verdict['problems']


def test_recomputation_catches_forgery_even_when_stored_hash_is_rewritten(tmp_path):
    """Hash-gate bypass (attacker rewrites the ledger hash too) must still fail recomputation."""
    import hashlib
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    freeze_delivery(db, 'REQ-OLD', 'inv-1', 'analyst-east', 'trend-analysis',
                    'coarsen_new', load_spec('counterexample-old.json'), root)
    freeze_delivery(db, 'REQ-NEW', 'inv-1', 'analyst-east', 'trend-analysis',
                    'coarsen_new', load_spec('counterexample-new.json'), root)
    # Split the generalized key of all but one row so one published class drops below k.
    package_path = root / 'REQ-NEW' / 'package.json'
    package = json.loads(package_path.read_text(encoding='utf-8'))
    quasi = package['levels']
    field = sorted(quasi)[0]
    package['rows'][0][field] = package['rows'][0][field] + '-forged'
    new_bytes = (json.dumps(package, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    package_path.write_bytes(new_bytes)
    con = connect(db)
    with con:
        con.execute('UPDATE delivery_request SET package_hash=? WHERE request_id=?',
                    (hashlib.sha256(new_bytes).hexdigest(), 'REQ-NEW'))
    con.close()
    verdict = verify_delivery(db, 'REQ-NEW', root)
    assert verdict['state'] == 'revoked'
    assert 'single_package_k_violated' in verdict['problems']


def test_pseudonyms_cannot_join_two_requests_and_salt_is_not_stored(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    freeze_delivery(db, 'REQ-J1', 'inv-1', 'analyst-east', 'x',
                    'hold_new', load_spec('counterexample-old.json'), root)
    freeze_delivery(db, 'REQ-J2', 'inv-1', 'analyst-east', 'x',
                    'hold_new', load_spec('counterexample-old.json'), root)
    p1 = {r['pseudonym'] for r in read_package(root, 'REQ-J1')['rows']}
    p2 = {r['pseudonym'] for r in read_package(root, 'REQ-J2')['rows']}
    assert p1.isdisjoint(p2)
    con = connect(db)
    columns = {r[1] for r in con.execute('PRAGMA table_info(delivery_request)')}
    assert 'package_salt_hash' in columns
    raw = '\n'.join(r[0] for r in con.execute(
        "SELECT sql FROM sqlite_master WHERE type='table'"))
    con.close()
    assert 'salt TEXT' not in raw


def test_inventory_source_change_blocks_freeze(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    changed = tmp_path / 'changed-inventory.csv'
    changed.write_text(CSV.read_text(encoding='utf-8').replace('s500', 's999'),
                       encoding='utf-8')
    spec = load_spec('counterexample-old.json')
    spec['inventory_csv_path'] = str(changed)
    with pytest.raises(ValueError, match='inventory_source_changed'):
        freeze_delivery(db, 'REQ-SRC', 'inv-1', 'analyst-east', 'x', 'hold_new', spec, root)


def test_coarsening_tie_break_is_deterministic(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    freeze_delivery(db, 'REQ-TIE-OLD', 'inv-1', 'analyst-east', 'trend-analysis',
                    'hold_new', load_spec('counterexample-old.json'), root)
    spec = load_spec('counterexample-new.json')
    # Two fields can each fix the intersection at the same cost; field-name order decides.
    spec['deliverable_fields'] = ['zone', 'age_band', 'score']
    spec['quasi_identifiers'] = ['age_band']
    spec['base_levels'] = {'age_band': 0}
    first = freeze_delivery(db, 'REQ-TIE', 'inv-1', 'analyst-east', 'trend-analysis',
                            'coarsen_new', spec, root)
    assert first['state'] == 'published'
    second_db = tmp_path / 'ledger2.db'
    initialize(second_db, FIX / 'config.json')
    load(second_db, FIX / 'events.jsonl')
    evaluate(second_db)
    register(second_db, 'inv-1', CSV)
    root2 = tmp_path / 'packages2'
    root2.mkdir()
    freeze_delivery(second_db, 'REQ-TIE-OLD', 'inv-1', 'analyst-east', 'trend-analysis',
                    'hold_new', load_spec('counterexample-old.json'), root2)
    freeze_delivery(second_db, 'REQ-TIE', 'inv-1', 'analyst-east', 'trend-analysis',
                    'coarsen_new', spec, root2)
    # Salts/pseudonyms are per-request randomness; the chosen generalization and published values
    # must be byte-identical across independent runs.
    p1 = read_package(root, 'REQ-TIE')
    p2 = read_package(root2, 'REQ-TIE')
    assert p1['levels'] == p2['levels']
    assert sorted((r['age_band'], r['score']) for r in p1['rows']) == \
        sorted((r['age_band'], r['score']) for r in p2['rows'])


def test_coarsening_is_minimum_loss_against_exhaustive_enumeration(tmp_path):
    from retaincase import delivery
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    freeze_delivery(db, 'REQ-OLD', 'inv-1', 'analyst-east', 'trend-analysis',
                    'hold_new', load_spec('counterexample-old.json'), root)
    spec = load_spec('counterexample-new.json')
    con = connect(db)
    receipt, inventory_rows, field_index = delivery._load_inventory(con, 'inv-1')
    info = delivery._validate_spec(spec, inventory_rows, field_index)
    run = con.execute('SELECT max(id) FROM run').fetchone()[0]
    from retaincase.requests import subject_release_gate
    info['subjects'] = sorted(s for s in info['subjects']
                              if subject_release_gate(con, s, run)['eligible'])
    prior = delivery._prior_classes(con, 'analyst-east')
    con.close()
    levels, evaluation = delivery._choose_coarsening(info, field_index, prior)
    # Brute-force every vector and confirm nothing feasible beats the engine's choice.
    ordered = sorted(info['quasi'])
    best_score = None
    for vector in delivery._enumerate_level_vectors(info['quasi'], info['lattice'],
                                                    info['base_levels']):
        cand = delivery._evaluate_levels(info['subjects'], field_index, info['quasi'], vector,
                                         info['lattice'], info['k'], info['max_suppression'],
                                         prior)
        if not cand['within_budget']:
            continue
        score = (delivery._vector_cost(vector, info['lattice']),
                 tuple(vector[f] for f in ordered),
                 len(cand['suppressed']),
                 tuple(sorted(cand['suppressed'])))
        best_score = score if best_score is None else min(best_score, score)
    engine_score = (delivery._vector_cost(levels, info['lattice']),
                    tuple(levels[f] for f in ordered),
                    len(evaluation['suppressed']),
                    tuple(sorted(evaluation['suppressed'])))
    assert engine_score == best_score


def test_coarsen_may_suppress_cross_violating_class_within_budget(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    freeze_delivery(db, 'REQ-OLD', 'inv-1', 'analyst-east', 'trend-analysis',
                    'hold_new', load_spec('counterexample-old.json'), root)
    # No coarser level exists, but the budget allows isolating the two violating classes.
    spec = load_spec('no-feasible-new.json')
    spec['max_suppression'] = 6
    result = freeze_delivery(db, 'REQ-SUP-CROSS', 'inv-1', 'analyst-east', 'trend-analysis',
                             'coarsen_new', spec, root)
    assert result['state'] == 'published'
    # hold_new with the same budget still refuses to publish at the original granularity.
    held = freeze_delivery(db, 'REQ-HOLD-CROSS', 'inv-1', 'analyst-east', 'trend-analysis',
                           'hold_new', spec, root)
    assert held['state'] == 'held'
    assert held['hold_reason'] == 'intersection_below_k'


def test_revoked_prior_package_still_counts_in_cross_checks(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    first = freeze_delivery(db, 'REQ-OLD', 'inv-1', 'analyst-east', 'trend-analysis',
                            'hold_new', load_spec('counterexample-old.json'), root)
    assert first['state'] == 'published'
    # Revoke the old package after tampering.
    target = root / 'REQ-OLD' / 'package.json'
    data = json.loads(target.read_text(encoding='utf-8'))
    data['rows'][0]['score'] = 'tampered'
    target.write_text(json.dumps(data), encoding='utf-8')
    assert verify_delivery(db, 'REQ-OLD', root)['state'] == 'revoked'
    # The same cross-package proposal must still be held: the recipient may retain the bytes.
    second = freeze_delivery(db, 'REQ-AFTER-REVOKE', 'inv-1', 'analyst-east', 'trend-analysis',
                             'hold_new', load_spec('counterexample-new.json'), root)
    assert second['state'] == 'held'
    assert second['hold_reason'] == 'intersection_below_k'


def test_changing_salt_never_makes_cross_publication_safe(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    freeze_delivery(db, 'REQ-OLD', 'inv-1', 'analyst-east', 'trend-analysis',
                    'hold_new', load_spec('counterexample-old.json'), root)
    # A second request with a brand-new salt/pseudonym space still fails on internal identities.
    second = freeze_delivery(db, 'REQ-SALT', 'inv-1', 'analyst-east', 'trend-analysis',
                             'hold_new', load_spec('counterexample-new.json'), root)
    assert second['state'] == 'held'
    assert second['hold_reason'] == 'intersection_below_k'
    # The same proposal to a different recipient has no observable prior packages and publishes.
    other = freeze_delivery(db, 'REQ-OTHER', 'inv-1', 'analyst-west', 'trend-analysis',
                            'hold_new', load_spec('counterexample-new.json'), root)
    assert other['state'] == 'published'


def test_report_uses_anonymous_group_numbers_without_identity_mapping(tmp_path):
    db, _ = ready(tmp_path)
    root = package_dir(tmp_path)
    freeze_delivery(db, 'REQ-OLD', 'inv-1', 'analyst-east', 'trend-analysis',
                    'coarsen_new', load_spec('counterexample-old.json'), root)
    coarse = freeze_delivery(db, 'REQ-NEW', 'inv-1', 'analyst-east', 'trend-analysis',
                             'coarsen_new', load_spec('counterexample-new.json'), root)
    result = delivery_report(db, 'REQ-NEW')
    assert coarse['state'] == 'published'
    assert result['intersections']
    for entry in result['intersections']:
        assert set(entry) == {'anonymous_no', 'prior_anonymous_no', 'overlap_count',
                              'prior_request_id', 'meets_k', 'protected'}
        assert isinstance(entry['anonymous_no'], int)
        assert 'class_no' not in entry and 'subject' not in entry
    import re
    blob = json.dumps(result, ensure_ascii=False)
    for subject in 'ABCDEG':
        assert not re.search(r'(?<![A-Za-z0-9_-])' + subject + r'(?![A-Za-z0-9_-])', blob)
