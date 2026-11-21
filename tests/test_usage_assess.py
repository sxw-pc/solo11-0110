"""Session assessment over frozen device-access scan logs.

Covers the four-line counter-example, shared vs independent device offsets,
the inclusive gap boundary, multi-device interleaving with exact extrema,
invalid pairings / impossible offsets, cutoff open intervals, idempotency,
tamper detection and isolation from the retention pipeline.
"""
import ast
import itertools
import json
import subprocess
import sys
from pathlib import Path

import pytest

from retaincase import ingest, rules, usage
from retaincase.store import connect
from retaincase.usage import (
    ALGORITHM_VERSION,
    _device_domains,
    _epoch,
    _guaranteed_extrema,
    _guaranteed_unavoidable_overlap,
    _load_scans,
    _pair_scans,
    _session_count_under_offsets,
)

FIXTURE = Path(__file__).resolve().parents[1] / 'fixtures'
CUTOFF_LATE = '2026-05-02T00:00:00Z'


def ready(db):
    ingest.initialize(db, FIXTURE / 'config.json')
    ingest.load(db, FIXTURE / 'events.jsonl')


def register(db, log_id, name):
    return usage.register(db, log_id, FIXTURE / name)


# --------------------------------------------------------------------------- #
# The canonical four-line counter-example
# --------------------------------------------------------------------------- #
def test_four_line_counterexample_reported_and_guaranteed(tmp_path):
    db = tmp_path / 'ledger.db'
    ready(db)
    register(db, 'shift-1', 'usage-scans.jsonl')

    reported = usage.assess(db, 'shift-1', 120, 'reported', CUTOFF_LATE, 1, 'rep-1')
    assert reported['state'] == '已判定'
    pair = reported['result']['pairs']['D|operator-1']
    assert pair['session_count'] == 1
    assert pair['sessions'][0]['member_scan_ids'] == ['e1', 'e2', 'e3', 'e4']
    assert reported['result']['overall_verdict'] == 'within_limit'

    guaranteed = usage.assess(db, 'shift-1', 120, 'guaranteed', CUTOFF_LATE, 1, 'gua-1')
    r = guaranteed['result']
    assert (r['min_total_sessions'], r['max_total_sessions']) == (1, 2)
    assert r['overall_verdict'] == 'indeterminate'
    # A max witness opens the 240s gap named in the brief; the engine returns
    # the smallest feasible offsets that attain the maximum, while the exact
    # assignment G1=-120, G2=+120 is itself a feasible two-session witness.
    scans = _load_scans(connect(db), 'shift-1')
    intervals = _pair_scans(scans, _epoch(CUTOFF_LATE))[2]
    max_off = r['max_witness']['offset_witness']
    assert _session_count_under_offsets(intervals, 120, max_off)[0] == 2
    brief_witness = {'G1': -120, 'G2': 120}
    assert _session_count_under_offsets(intervals, 120, brief_witness)[0] == 2
    min_off = r['min_witness']['offset_witness']
    assert _session_count_under_offsets(intervals, 120, min_off)[0] == 1
    for off in (min_off, max_off):  # every witness satisfies ±error_seconds
        for device, value in off.items():
            assert abs(value) <= 120
    # domains expose the declared integer offset space explicitly
    assert r['device_offset_domains'] == {
        'G1': {'min_offset': -120, 'max_offset': 120},
        'G2': {'min_offset': -120, 'max_offset': 120}}


def test_guaranteed_extrema_match_brute_force_on_four_lines(tmp_path):
    db = tmp_path / 'ledger.db'
    ready(db)
    register(db, 'shift-1', 'usage-scans.jsonl')
    scans = _load_scans(connect(db), 'shift-1')
    intervals = _pair_scans(scans, _epoch(CUTOFF_LATE))[2]
    domains = _device_domains(scans)
    counts = set()
    for o1 in range(-120, 121):
        for o2 in range(-120, 121):
            counts.add(_session_count_under_offsets(
                intervals, 120, {'G1': o1, 'G2': o2})[0])
    ext = _guaranteed_extrema(intervals, domains, 120)
    assert (ext['min_total_sessions'], ext['max_total_sessions']) == (
        min(counts), max(counts)) == (1, 2)


# --------------------------------------------------------------------------- #
# Shared device offset versus independent per-scan drift
# --------------------------------------------------------------------------- #
def test_shared_device_offset_is_one_constant_per_device(tmp_path):
    db = tmp_path / 'ledger.db'
    ready(db)
    register(db, 'shared', 'usage-shared-offset.jsonl')
    r = usage.assess(db, 'shared', 120, 'guaranteed', CUTOFF_LATE, 1, 'sh-1')['result']
    assert (r['min_total_sessions'], r['max_total_sessions']) == (1, 2)
    scans = _load_scans(connect(db), 'shared')
    intervals = _pair_scans(scans, _epoch(CUTOFF_LATE))[2]
    # Every witness moves both scans of a device by the same constant.
    for witness in (r['min_witness'], r['max_witness']):
        off = witness['offset_witness']
        assert _session_count_under_offsets(intervals, 120, off)[0] == \
            witness['total_sessions']
        for device, value in off.items():
            device_scans = [s for s in scans if s['device'] == device]
            assert all(abs(value) <= s['error_seconds'] for s in device_scans)
            assert len({s['device'] for s in device_scans}) == 1


def test_per_scan_independent_drift_is_rejected_by_shared_constant_model(tmp_path):
    """The forbidden per-scan drift model can move individual scans in ways no
    shared per-device constant can reproduce; the engine's witnesses must
    always be one constant per device."""
    db = tmp_path / 'ledger.db'
    ready(db)
    raw = '\n'.join([
        json.dumps({'event_id': 's1', 'subject': 'D', 'actor': 'op',
                    'device': 'V1', 'action': 'enter',
                    'reported_at': '2026-05-01T10:00:00Z', 'error_seconds': 2}),
        json.dumps({'event_id': 's2', 'subject': 'D', 'actor': 'op',
                    'device': 'V1', 'action': 'exit',
                    'reported_at': '2026-05-01T10:05:00Z', 'error_seconds': 2}),
        json.dumps({'event_id': 's3', 'subject': 'D', 'actor': 'op',
                    'device': 'V2', 'action': 'enter',
                    'reported_at': '2026-05-01T10:05:04Z', 'error_seconds': 2}),
        json.dumps({'event_id': 's4', 'subject': 'D', 'actor': 'op',
                    'device': 'V2', 'action': 'exit',
                    'reported_at': '2026-05-01T10:10:04Z',
                    'error_seconds': 2})])
    source = tmp_path / 'drift.jsonl'
    source.write_text(raw, encoding='utf-8')
    usage.register(db, 'drift', source)
    scans = _load_scans(connect(db), 'drift')
    intervals = _pair_scans(scans, _epoch(CUTOFF_LATE))[2]
    legal = usage.assess(db, 'drift', 6, 'guaranteed', CUTOFF_LATE, 1, 'dr-1')['result']

    # Illegal model: each scan drifts independently within ±2.  Enumerate it
    # and show it admits configurations that split a device's two scans —
    # something the shared-constant witness space never contains.
    splits_seen = 0
    drift_counts = set()
    for combo in itertools.product(range(-2, 3), repeat=4):
        if combo[0] != combo[1] or combo[2] != combo[3]:
            splits_seen += 1
        shifted = []
        for iv, (enter_off, exit_off) in zip(intervals, (combo[:2], combo[2:])):
            shifted.append({'start': iv['enter_epoch'] + enter_off,
                            'end': iv['exit_epoch'] + exit_off,
                            'device': iv['device'], 'enter_id': iv['enter_id'],
                            'exit_id': iv['exit_id'], 'subject': iv['subject'],
                            'actor': iv['actor']})
        drift_counts.add(len(usage._merge_intervals(shifted, 6)))
    assert splits_seen > 0
    assert drift_counts == {1, 2}

    # The legal model also spans both session counts, but every witness is a
    # single shared constant per device and replays to the claimed extremum.
    assert (legal['min_total_sessions'], legal['max_total_sessions']) == (1, 2)
    for witness, claimed in ((legal['min_witness'], legal['min_total_sessions']),
                             (legal['max_witness'], legal['max_total_sessions'])):
        off = witness['offset_witness']
        assert _session_count_under_offsets(intervals, 6, off)[0] == claimed
        per_device = {}
        for s in scans:
            per_device.setdefault(s['device'], set()).add(off[s['device']])
        assert all(len(vals) == 1 for vals in per_device.values())


# --------------------------------------------------------------------------- #
# Gap equality boundary: gap_seconds equal still merges
# --------------------------------------------------------------------------- #
def test_gap_equality_boundary_merges(tmp_path):
    db = tmp_path / 'ledger.db'
    ready(db)
    register(db, 'gap', 'usage-gap-boundary.jsonl')
    equal = usage.assess(db, 'gap', 300, 'reported', CUTOFF_LATE, 1, 'gb-eq')
    assert equal['result']['total_sessions'] == 1
    one_less = usage.assess(db, 'gap', 299, 'reported', CUTOFF_LATE, 1, 'gb-lt')
    assert one_less['result']['total_sessions'] == 2
    # Same boundary semantics under guaranteed offsets (zero error here).
    g = usage.assess(db, 'gap', 300, 'guaranteed', CUTOFF_LATE, 1, 'gb-g')
    assert (g['result']['min_total_sessions'],
            g['result']['max_total_sessions']) == (1, 2)


# --------------------------------------------------------------------------- #
# Multi-device interleaving with a 12-scan / hours-wide error scale
# --------------------------------------------------------------------------- #
def test_multi_device_interleaving_exact_extrema_and_witnesses(tmp_path):
    db = tmp_path / 'ledger.db'
    ready(db)
    register(db, 'multi', 'usage-multi-device.jsonl')
    body = usage.assess(db, 'multi', 300, 'guaranteed', CUTOFF_LATE, 3, 'md-g')
    r = body['result']
    assert body['state'] == '已判定'
    assert r['min_total_sessions'] <= r['max_total_sessions']
    scans = _load_scans(connect(db), 'multi')
    intervals = _pair_scans(scans, _epoch(CUTOFF_LATE))[2]
    assert len(intervals) == 6  # 12 scans -> six closed device intervals
    for witness, claimed in ((r['min_witness'], r['min_total_sessions']),
                             (r['max_witness'], r['max_total_sessions'])):
        off = witness['offset_witness']
        # one shared constant per device, feasible against every device scan
        for s in scans:
            assert abs(off[s['device']]) <= s['error_seconds']
        assert _session_count_under_offsets(intervals, 300, off)[0] == claimed
    # reported timeline answers the duty analyst's raw view
    reported = usage.assess(db, 'multi', 300, 'reported', CUTOFF_LATE, 3, 'md-r')
    assert reported['result']['total_sessions'] == 6
    assert reported['result']['overall_verdict'] == 'limit_exceeded'


def test_extrema_engine_is_complete_on_random_three_device_cases():
    """Differential check against exhaustive enumeration; runtime must not
    depend on error-window width (no grid over the offset domain)."""
    import random
    random.seed(20260501)
    for _ in range(40):
        devices = ['G1', 'G2', 'G3']
        intervals, t = [], 100000
        for d in devices:
            for _ in range(2):
                a = t + random.randint(0, 500)
                b = a + random.randint(30, 150)
                intervals.append({'subject': 'D', 'actor': 'A', 'device': d,
                                  'enter_id': f'{d}-{a}', 'exit_id': f'{d}-{b}',
                                  'enter_epoch': a, 'exit_epoch': b,
                                  'error_seconds': 0})
                t += 80
        errors = {d: random.randint(0, 20) for d in devices}
        for iv in intervals:
            iv['error_seconds'] = errors[iv['device']]
        domains = _device_domains([{'device': d, 'error_seconds': e}
                                   for d, e in errors.items()])
        gap = random.choice([0, 60, 120, 240])
        if _guaranteed_unavoidable_overlap(intervals, domains):
            continue
        ext = _guaranteed_extrema(intervals, domains, gap)
        brute = {_session_count_under_offsets(
            intervals, gap, dict(zip(devices, combo)))[0]
            for combo in itertools.product(
                *[range(domains[d]['min_offset'], domains[d]['max_offset'] + 1)
                  for d in devices])}
        assert (ext['min_total_sessions'], ext['max_total_sessions']) == (
            min(brute), max(brute))


# --------------------------------------------------------------------------- #
# Invalid pairings and impossible offset intersections
# --------------------------------------------------------------------------- #
def test_exit_without_enter_is_pending_reason_not_zero_sessions(tmp_path):
    db = tmp_path / 'ledger.db'
    ready(db)
    register(db, 'bad-exit', 'usage-invalid-exit.jsonl')
    for contract in ('reported', 'guaranteed'):
        body = usage.assess(db, 'bad-exit', 120, contract, CUTOFF_LATE, 1,
                            f'bad-{contract}')
        assert body['state'] == '待核'
        assert body['result'] is None
        codes = {p['code'] for p in body['problems']}
        assert 'exit_without_enter' in codes


def test_impossible_offset_intersection_detected(tmp_path):
    db = tmp_path / 'ledger.db'
    ready(db)
    register(db, 'imp', 'usage-impossible-offset.jsonl')
    body = usage.assess(db, 'imp', 120, 'guaranteed', CUTOFF_LATE, 1, 'imp-g')
    assert body['state'] == '待核'
    assert any(p['code'] == 'impossible_offset_intersection' for p in body['problems'])
    # On the raw reported timeline the same rows are a strict device overlap.
    reported = usage.assess(db, 'imp', 120, 'reported', CUTOFF_LATE, 1, 'imp-r')
    assert any(p['code'] == 'cross_device_overlap_reported'
               for p in reported['problems'])


def test_duplicate_enter_and_missing_exit(tmp_path):
    db = tmp_path / 'ledger.db'
    ready(db)
    raw = '\n'.join([
        json.dumps({'event_id': 'd1', 'subject': 'D', 'actor': 'op',
                    'device': 'Z1', 'action': 'enter',
                    'reported_at': '2026-05-01T10:00:00Z', 'error_seconds': 30}),
        json.dumps({'event_id': 'd2', 'subject': 'D', 'actor': 'op',
                    'device': 'Z1', 'action': 'enter',
                    'reported_at': '2026-05-01T10:01:00Z', 'error_seconds': 30}),
        json.dumps({'event_id': 'd3', 'subject': 'D', 'actor': 'op',
                    'device': 'Z2', 'action': 'enter',
                    'reported_at': '2026-05-01T11:00:00Z', 'error_seconds': 30}),
        json.dumps({'event_id': 'd4', 'subject': 'D', 'actor': 'op',
                    'device': 'Z2', 'action': 'exit',
                    'reported_at': '2026-05-01T11:05:00Z', 'error_seconds': 30})])
    path = tmp_path / 'dup.jsonl'
    path.write_text(raw, encoding='utf-8')
    usage.register(db, 'dup', path)
    body = usage.assess(db, 'dup', 120, 'reported', CUTOFF_LATE, 1, 'dup-1')
    codes = {p['code'] for p in body['problems']}
    assert {'duplicate_enter_without_exit', 'missing_exit'} <= codes
    assert body['state'] == '待核' and body['result'] is None


def test_enter_not_before_exit_and_timeless_scan_rejected(tmp_path):
    db = tmp_path / 'ledger.db'
    ready(db)
    raw = '\n'.join([
        json.dumps({'event_id': 'n1', 'subject': 'D', 'actor': 'op',
                    'device': 'Z3', 'action': 'enter',
                    'reported_at': '2026-05-01T10:10:00Z', 'error_seconds': 30}),
        json.dumps({'event_id': 'n2', 'subject': 'D', 'actor': 'op',
                    'device': 'Z3', 'action': 'exit',
                    'reported_at': '2026-05-01T10:05:00Z', 'error_seconds': 30})])
    path = tmp_path / 'reversed.jsonl'
    path.write_text(raw, encoding='utf-8')
    usage.register(db, 'rev', path)
    body = usage.assess(db, 'rev', 120, 'reported', CUTOFF_LATE, 1, 'rev-1')
    # sorted by time the early exit has no preceding enter; the later enter
    # then has no exit — both structural reasons are surfaced, never zeroed.
    codes = {p['code'] for p in body['problems']}
    assert {'exit_without_enter', 'missing_exit'} <= codes
    assert body['state'] == '待核' and body['result'] is None


def test_enter_not_before_exit_with_nested_pair(tmp_path):
    # enter A, enter B, exit A, exit B: the first exit closes enter A, but
    # the remaining enter B nests past it and eventually misses its exit.
    db = tmp_path / 'ledger.db'
    ready(db)
    raw = '\n'.join([
        json.dumps({'event_id': 'q1', 'subject': 'D', 'actor': 'op',
                    'device': 'Z4', 'action': 'enter',
                    'reported_at': '2026-05-01T10:00:00Z', 'error_seconds': 30}),
        json.dumps({'event_id': 'q2', 'subject': 'D', 'actor': 'op',
                    'device': 'Z4', 'action': 'enter',
                    'reported_at': '2026-05-01T10:02:00Z', 'error_seconds': 30}),
        json.dumps({'event_id': 'q3', 'subject': 'D', 'actor': 'op',
                    'device': 'Z4', 'action': 'exit',
                    'reported_at': '2026-05-01T10:05:00Z', 'error_seconds': 30}),
        json.dumps({'event_id': 'q4', 'subject': 'D', 'actor': 'op',
                    'device': 'Z4', 'action': 'exit',
                    'reported_at': '2026-05-01T10:08:00Z', 'error_seconds': 30})])
    path = tmp_path / 'nested.jsonl'
    path.write_text(raw, encoding='utf-8')
    usage.register(db, 'nest', path)
    body = usage.assess(db, 'nest', 120, 'reported', CUTOFF_LATE, 1, 'nest-1')
    assert any(p['code'] == 'duplicate_enter_without_exit' for p in body['problems'])
    assert body['state'] == '待核'

# --------------------------------------------------------------------------- #
# Cutoff: rows after cutoff excluded; an open interval is pending review
# --------------------------------------------------------------------------- #
def test_cutoff_open_interval_is_pending(tmp_path):
    db = tmp_path / 'ledger.db'
    ready(db)
    register(db, 'cut', 'usage-cutoff.jsonl')
    inside = usage.assess(db, 'cut', 120, 'reported',
                          '2026-05-01T10:02:00Z', 1, 'cut-in')
    assert inside['state'] == '待核'
    # the not-yet-seen exit of the open interval is excluded just like later rows
    assert inside['input_summary']['excluded_after_cutoff_event_ids'] == \
        ['u2', 'u3', 'u4']
    pair = inside['result']['pairs']['D|operator-1']
    assert pair['open_intervals'][0]['enter_id'] == 'u1'
    assert pair['open_intervals'][0]['pending_exit_ids'] == ['u2']
    assert pair['verdict'] == 'indeterminate'
    g = usage.assess(db, 'cut', 120, 'guaranteed',
                     '2026-05-01T10:02:00Z', 1, 'cut-g')
    assert g['state'] == '待核'
    assert g['result']['overall_verdict'] == 'indeterminate'
    # A cutoff before any scan counts nothing but is not silently zero.
    early = usage.assess(db, 'cut', 120, 'reported',
                         '2026-05-01T09:00:00Z', 1, 'cut-early')
    assert early['input_summary']['counted_scan_count'] == 0
    assert early['input_summary']['excluded_after_cutoff_event_ids'] == \
        ['u1', 'u2', 'u3', 'u4']


# --------------------------------------------------------------------------- #
# Versioning, idempotency and tamper evidence
# --------------------------------------------------------------------------- #
def test_assessment_idempotent_same_params_conflicting_params_rejected(tmp_path):
    db = tmp_path / 'ledger.db'
    ready(db)
    register(db, 'shift-1', 'usage-scans.jsonl')
    first = usage.assess(db, 'shift-1', 120, 'guaranteed', CUTOFF_LATE, 1, 'A1')
    again = usage.assess(db, 'shift-1', 120, 'guaranteed', CUTOFF_LATE, 1, 'A1')
    assert again == first
    with pytest.raises(ValueError, match='assessment_identity_conflict'):
        usage.assess(db, 'shift-1', 121, 'guaranteed', CUTOFF_LATE, 1, 'A1')
    with pytest.raises(ValueError, match='assessment_identity_conflict'):
        usage.assess(db, 'shift-1', 120, 'reported', CUTOFF_LATE, 1, 'A1')
    with pytest.raises(ValueError, match='assessment_identity_conflict'):
        usage.assess(db, 'shift-1', 120, 'guaranteed', CUTOFF_LATE, 2, 'A1')
    # A fresh assessment id is an independent frozen record.
    other = usage.assess(db, 'shift-1', 121, 'guaranteed', CUTOFF_LATE, 1, 'A2')
    assert other['assessment_id'] == 'A2'
    assert other['param_hash'] != first['param_hash']
    assert first['algorithm_version'] == ALGORITHM_VERSION


def test_new_log_version_cannot_overwrite_old_assessment(tmp_path):
    db = tmp_path / 'ledger.db'
    ready(db)
    register(db, 'shift-1', 'usage-scans.jsonl')
    first = usage.assess(db, 'shift-1', 120, 'guaranteed', CUTOFF_LATE, 1, 'A1')
    changed = tmp_path / 'changed.jsonl'
    changed.write_bytes((FIXTURE / 'usage-scans.jsonl').read_bytes()
                        .replace(b'10:10:00Z', b'10:11:00Z'))
    with pytest.raises(ValueError, match='usage_log_identity_conflict'):
        usage.register(db, 'shift-1', changed)
    # The frozen assessment still verifies against the original log.
    assert usage.verify(db, 'A1') == []
    assert first['source_hash']


def test_verify_rejects_tampered_scans_thresholds_and_witnesses(tmp_path):
    db = tmp_path / 'ledger.db'
    ready(db)
    register(db, 'shift-1', 'usage-scans.jsonl')
    usage.assess(db, 'shift-1', 120, 'guaranteed', CUTOFF_LATE, 1, 'A1')
    assert usage.verify(db, 'A1') == []

    con = connect(db)
    # 1) tamper a frozen scan row
    with con:
        con.execute("UPDATE usage_scan SET reported_at=? WHERE event_id='e4'",
                    ('2026-05-01T10:11:00Z',))
    problems = usage.verify(db, 'A1')
    assert any('usage_scan_table_drift' in p or 'conclusion_drift' in p
               for p in problems)
    con.close()

    # rebuild a clean ledger for the threshold/witness tamper cases
    db2 = tmp_path / 'ledger2.db'
    ready(db2)
    register(db2, 'shift-1', 'usage-scans.jsonl')
    usage.assess(db2, 'shift-1', 120, 'guaranteed', CUTOFF_LATE, 1, 'A1')
    con = connect(db2)
    with con:
        con.execute('UPDATE usage_assessment SET session_limit=2 WHERE id=?', ('A1',))
    assert any('param_hash' in p for p in usage.verify(db2, 'A1'))
    con.close()

    db3 = tmp_path / 'ledger3.db'
    ready(db3)
    register(db3, 'shift-1', 'usage-scans.jsonl')
    body = usage.assess(db3, 'shift-1', 120, 'guaranteed', CUTOFF_LATE, 1, 'A1')
    tampered = json.loads(json.dumps(body))
    tampered['result']['max_witness']['offset_witness'] = {'G1': 0, 'G2': 0}
    con = connect(db3)
    with con:
        con.execute('UPDATE usage_assessment SET body=? WHERE id=?',
                    (json.dumps(tampered, ensure_ascii=False, sort_keys=True), 'A1'))
    con.close()
    problems = usage.verify(db3, 'A1')
    assert any('conclusion_drift' in p for p in problems)


def test_verify_rejects_tampered_raw_log_bytes(tmp_path):
    db = tmp_path / 'ledger.db'
    ready(db)
    register(db, 'shift-1', 'usage-scans.jsonl')
    usage.assess(db, 'shift-1', 120, 'reported', CUTOFF_LATE, 1, 'A1')
    con = connect(db)
    with con:
        row = con.execute('SELECT source FROM usage_log WHERE id=?',
                          ('shift-1',)).fetchone()
        con.execute('UPDATE usage_log SET source=? WHERE id=?',
                    (row['source'].replace(b'operator-1', b'operator-9'),
                     'shift-1'))
    con.close()
    problems = usage.verify(db, 'A1')
    assert any('source_hash' in p for p in problems)


# --------------------------------------------------------------------------- #
# Isolation: session conclusions never feed retention / requests / handoff
# --------------------------------------------------------------------------- #
def test_usage_assessment_does_not_change_retention_pipeline(tmp_path):
    db = tmp_path / 'ledger.db'
    ready(db)
    baseline = rules.evaluate(db)
    register(db, 'shift-1', 'usage-scans.jsonl')
    usage.assess(db, 'shift-1', 120, 'reported', CUTOFF_LATE, 1, 'A1')
    usage.assess(db, 'shift-1', 120, 'guaranteed', CUTOFF_LATE, 1, 'A2')
    assert rules.evaluate(db) == baseline
    # raw summary contract stays scan/actor/device counts only
    assert usage.summary(db, 'shift-1') == {'scans': 4, 'actors': 1, 'devices': 2}


def test_parameter_validation(tmp_path):
    db = tmp_path / 'ledger.db'
    ready(db)
    register(db, 'shift-1', 'usage-scans.jsonl')
    with pytest.raises(ValueError, match='bad_gap_seconds'):
        usage.assess(db, 'shift-1', -1, 'reported', CUTOFF_LATE, 1, 'X')
    with pytest.raises(ValueError, match='bad_clock_contract'):
        usage.assess(db, 'shift-1', 120, 'speculative', CUTOFF_LATE, 1, 'X')
    with pytest.raises(ValueError, match='bad_session_limit'):
        usage.assess(db, 'shift-1', 120, 'reported', CUTOFF_LATE, -1, 'X')
    with pytest.raises(ValueError, match='unknown_usage_log'):
        usage.assess(db, 'nope', 120, 'reported', CUTOFF_LATE, 1, 'X')
    with pytest.raises(ValueError, match='unknown_assessment'):
        usage.verify(db, 'nope')


def test_cli_usage_assess_and_verify(tmp_path):
    db = tmp_path / 'ledger.db'
    ready(db)

    def run(*args):
        proc = subprocess.run(
            [sys.executable, '-B', '-m', 'retaincase', *args],
            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr
        return proc.stdout
    run('usage-register', '--db', str(db), '--id', 'shift-1',
        '--source', str(FIXTURE / 'usage-scans.jsonl'))
    out = run('usage-assess', '--db', str(db), '--id', 'shift-1',
              '--gap', '120', '--contract', 'guaranteed',
              '--cutoff', CUTOFF_LATE, '--limit', '1', '--assessment', 'CLI1')
    body = ast.literal_eval(out)
    assert body['result']['min_total_sessions'] == 1
    verified = ast.literal_eval(run('usage-verify', '--db', str(db),
                                    '--assessment', 'CLI1'))
    assert verified['ok'] is True and verified['integrity_problems'] == []
