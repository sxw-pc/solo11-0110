import itertools
import json
import os
import random
import subprocess
import sys
from pathlib import Path

import pytest

from retaincase import ingest, rules, usage
from retaincase.requests import triage
from retaincase.store import connect

FIX = Path(__file__).resolve().parents[1] / 'fixtures'
CUTOFF = '2026-05-02T00:00:00Z'


def scan(event_id, device, action, at, error=120, subject='D', actor='operator-1'):
    return {'event_id': event_id, 'subject': subject, 'actor': actor, 'device': device,
            'action': action, 'reported_at': at, 'error_seconds': error}


def ts(hour, minute=0, second=0):
    return f'2026-05-01T{hour:02d}:{minute:02d}:{second:02d}Z'


def write_log(tmp_path, rows, name='scans.jsonl'):
    path = tmp_path / name
    path.write_text('\n'.join(json.dumps(row) for row in rows) + '\n', encoding='utf-8')
    return path


def ready(tmp_path, rows=None, log_id='shift-1', name='ledger.db'):
    db = tmp_path / name
    ingest.initialize(db, FIX / 'config.json')
    ingest.load(db, FIX / 'events.jsonl')
    if rows is not None:
        usage.register(db, log_id, write_log(tmp_path, rows, f'{log_id}.jsonl'))
    return db


def group_of(result, subject='D', actor='operator-1'):
    matched = [g for g in result['groups'] if g['subject'] == subject and g['actor'] == actor]
    assert len(matched) == 1
    return matched[0]


def replay(result_rows, witness, gap):
    """Independent session count at a witness offset assignment."""
    points = sorted((start + witness[device], end + witness[device])
                    for start, end, device in result_rows)
    count, end_so_far = 0, None
    for start, end in points:
        if end_so_far is None or start - end_so_far > gap:
            count += 1
            end_so_far = end
        else:
            end_so_far = max(end_so_far, end)
    return count


def test_four_line_counterexample_reported_and_guaranteed(tmp_path):
    db = ready(tmp_path)
    usage.register(db, 'shift-1', FIX / 'usage-scans.jsonl')
    reported = usage.assess(db, 'shift-1', 120, 'reported', CUTOFF, 1, 'A-reported')
    group = group_of(reported)
    assert group['reported']['sessions'] == 1
    assert group['reported']['members'] == [['e1', 'e2', 'e3', 'e4']]
    assert reported['verdict'] == 'pass'
    assert reported['status'] == 'ok'

    guaranteed = usage.assess(db, 'shift-1', 120, 'guaranteed', CUTOFF, 1, 'A-guaranteed')
    payload = group_of(guaranteed)['guaranteed']
    # G1 may drift -120s and G2 +120s, stretching the actual gap to 240s > 120s.
    assert (payload['min'], payload['max']) == (1, 2)
    assert guaranteed['verdict'] == 'indeterminate'
    assert payload['min_sessions'] == [['e1', 'e2', 'e3', 'e4']]
    assert payload['max_sessions'] == [['e1', 'e2'], ['e3', 'e4']]
    intervals = [(0, 300, 'G1'), (300, 600, 'G2')]
    for witness, bound in ((payload['min_witness'], 1), (payload['max_witness'], 2)):
        assert set(witness) == {'G1', 'G2'}
        assert all(abs(offset) <= 120 for offset in witness.values())
        assert replay(intervals, witness, 120) == bound
    # A single greedy offset assignment cannot stand in for the range: both
    # bounds are exact and certified by their own replayable witnesses.
    assert usage.verify(db, 'A-guaranteed') == []
    assert usage.verify(db, 'A-reported') == []


def test_shared_device_offset_is_not_per_scan_independence(tmp_path):
    same_device = [scan('a1', 'G1', 'enter', ts(10, 0)), scan('a2', 'G1', 'exit', ts(10, 5)),
                   scan('a3', 'G1', 'enter', ts(10, 10)), scan('a4', 'G1', 'exit', ts(10, 15))]
    db = ready(tmp_path, same_device, log_id='same-device')
    result = usage.assess(db, 'same-device', 120, 'guaranteed', CUTOFF, 1, 'same')
    payload = group_of(result)['guaranteed']
    # One shared offset per device: the 300s gap can never shrink to merge.
    assert (payload['min'], payload['max']) == (2, 2)
    assert result['verdict'] == 'fail'

    cross_device = [scan('a1', 'G1', 'enter', ts(10, 0)), scan('a2', 'G1', 'exit', ts(10, 5)),
                    scan('a3', 'G2', 'enter', ts(10, 10)), scan('a4', 'G2', 'exit', ts(10, 15))]
    db2 = ready(tmp_path, cross_device, log_id='cross-device', name='other.db')
    result2 = usage.assess(db2, 'cross-device', 120, 'guaranteed', CUTOFF, 1, 'cross')
    payload2 = group_of(result2)['guaranteed']
    # Independent device offsets can close the gap to 60s or stretch it to 540s.
    assert (payload2['min'], payload2['max']) == (1, 2)
    assert result2['verdict'] == 'indeterminate'


def test_gap_equality_boundary_merges(tmp_path):
    rows = [scan('a1', 'G1', 'enter', ts(10, 0), error=0), scan('a2', 'G1', 'exit', ts(10, 5), error=0),
            scan('a3', 'G2', 'enter', ts(10, 7), error=0), scan('a4', 'G2', 'exit', ts(10, 12), error=0)]
    db = ready(tmp_path, rows, log_id='edge-equal')
    for contract in ('reported', 'guaranteed'):
        result = usage.assess(db, 'edge-equal', 120, contract, CUTOFF, 1, f'eq-{contract}')
        group = group_of(result)
        assert group['verdict'] == 'pass'
        if contract == 'reported':
            assert group['reported']['sessions'] == 1  # gap of exactly 120 merges
        else:
            assert (group['guaranteed']['min'], group['guaranteed']['max']) == (1, 1)
    later = [scan('a1', 'G1', 'enter', ts(10, 0), error=0), scan('a2', 'G1', 'exit', ts(10, 5), error=0),
             scan('a3', 'G2', 'enter', ts(10, 7, 1), error=0), scan('a4', 'G2', 'exit', ts(10, 12, 1), error=0)]
    db2 = ready(tmp_path, later, log_id='edge-over', name='over.db')
    result = usage.assess(db2, 'edge-over', 120, 'reported', CUTOFF, 1, 'over')
    assert group_of(result)['reported']['sessions'] == 2  # 121s exceeds the gap
    assert result['verdict'] == 'fail'


def test_multi_device_interleave_exact_extrema(tmp_path):
    db = ready(tmp_path)
    usage.register(db, 'multi', FIX / 'usage-scans-multi.jsonl')
    reported = usage.assess(db, 'multi', 1800, 'reported', CUTOFF, 3, 'M-reported')
    assert reported['input_summary'] == {'scans_total': 16, 'scans_counted': 16, 'subjects': 2,
                                         'actors': 2, 'devices': 3, 'groups': 2}
    assert group_of(reported)['reported']['sessions'] == 3
    assert group_of(reported, 'C', 'operator-2')['reported']['sessions'] == 2
    assert reported['verdict'] == 'pass'

    guaranteed = usage.assess(db, 'multi', 1800, 'guaranteed', CUTOFF, 4, 'M-guaranteed')
    main = group_of(guaranteed)['guaranteed']
    # Hand-derived exact extrema: one bridge between the two triples is
    # impossible (min 2); one cyclic separation is impossible (max 5).
    assert (main['min'], main['max']) == (2, 5)
    other = group_of(guaranteed, 'C', 'operator-2')['guaranteed']
    assert (other['min'], other['max']) == (1, 2)
    assert guaranteed['verdict'] == 'indeterminate'

    base = 1_777_737_600  # 2026-05-01T00:00:00Z
    hour = 3600
    intervals = ([(base + 8 * hour, base + 9 * hour, 'G1'), (base + 12 * hour, base + 13 * hour, 'G1'),
                  (base + 9.5 * hour, base + 10.5 * hour, 'G2'), (base + 14 * hour, base + 15 * hour, 'G2'),
                  (base + 11 * hour, base + 11.5 * hour, 'G3'), (base + 16 * hour, base + 17 * hour, 'G3')])
    intervals = [(int(s), int(e), d) for s, e, d in intervals]
    for witness, bound in ((main['min_witness'], 2), (main['max_witness'], 5)):
        assert all(abs(offset) <= 3600 for offset in witness.values())
        assert replay(intervals, witness, 1800) == bound
    # The max witness reorders intervals across devices: no fixed reported
    # order could produce five sessions here.
    assert main['max'] > group_of(reported)['reported']['sessions'] + 1

    assert usage.assess(db, 'multi', 1800, 'guaranteed', CUTOFF, 5, 'M-limit-5')['verdict'] == 'pass'
    assert usage.assess(db, 'multi', 1800, 'guaranteed', CUTOFF, 1, 'M-limit-1')['verdict'] == 'fail'
    assert usage.assess(db, 'multi', 1800, 'reported', CUTOFF, 2, 'M-rep-2')['verdict'] == 'fail'
    assert usage.verify(db, 'M-guaranteed') == []


def test_invalid_pairing_gives_concrete_pending_reasons(tmp_path):
    cases = {
        'duplicate_enter': [scan('a1', 'G1', 'enter', ts(10, 0)), scan('a2', 'G1', 'enter', ts(10, 1)),
                            scan('a3', 'G1', 'exit', ts(10, 2))],
        'exit_without_enter': [scan('a1', 'G1', 'exit', ts(10, 0))],
        'unclosed_interval': [scan('a1', 'G1', 'enter', ts(10, 0)), scan('a2', 'G1', 'exit', ts(10, 5)),
                              scan('a3', 'G1', 'enter', ts(10, 6))],
        'cross_device_overlap': [scan('a1', 'G1', 'enter', ts(10, 0)), scan('a2', 'G1', 'exit', ts(10, 5)),
                                 scan('a3', 'G2', 'enter', ts(10, 4)), scan('a4', 'G2', 'exit', ts(10, 9))],
        'impossible_error_intersection': [
            scan('a1', 'G1', 'enter', ts(10, 0), error=60), scan('a2', 'G1', 'exit', ts(11, 0), error=60),
            scan('a3', 'G2', 'enter', ts(10, 30), error=60), scan('a4', 'G2', 'exit', ts(11, 30), error=60)],
    }
    for code, rows in cases.items():
        db = ready(tmp_path / code, rows, log_id='bad')
        result = usage.assess(db, 'bad', 120, 'reported', CUTOFF, 1, 'A')
        group = group_of(result)
        assert result['status'] == 'pending_review'
        assert result['verdict'] == 'pending_review'
        assert [r['code'] for r in group['reasons']] == [code]
        # Invalid logs are never silently counted as zero sessions.
        assert group['reported'] is None and group['guaranteed'] is None
        assert usage.verify(db, 'A') == []


def test_cutoff_marks_unclosed_interval_pending(tmp_path):
    db = ready(tmp_path)
    usage.register(db, 'shift-1', FIX / 'usage-scans.jsonl')
    result = usage.assess(db, 'shift-1', 120, 'reported', '2026-05-01T10:06:00Z', 1, 'cut')
    group = group_of(result)
    assert result['status'] == 'pending_review'
    assert [r['code'] for r in group['reasons']] == ['unclosed_interval']
    assert 'after cutoff' in group['reasons'][0]['detail']
    assert result['input_summary']['scans_counted'] == 3

    empty = usage.assess(db, 'shift-1', 120, 'reported', '2026-05-01T09:00:00Z', 1, 'early')
    assert empty['input_summary']['scans_counted'] == 0
    assert empty['groups'] == [] and empty['verdict'] == 'pass'


def test_assessment_idempotent_and_conflicting_params(tmp_path):
    db = ready(tmp_path)
    usage.register(db, 'shift-1', FIX / 'usage-scans.jsonl')
    first = usage.assess(db, 'shift-1', 120, 'guaranteed', CUTOFF, 1, 'A1')
    assert usage.assess(db, 'shift-1', 120, 'guaranteed', CUTOFF, 1, 'A1') == first
    con = connect(db)
    assert con.execute('SELECT count(*) FROM usage_assessment').fetchone()[0] == 1
    con.close()
    for kwargs in ({'gap_seconds': 121}, {'clock_contract': 'reported'},
                   {'cutoff': '2026-05-03T00:00:00Z'}, {'session_limit': 2}):
        params = dict(log_id='shift-1', gap_seconds=120, clock_contract='guaranteed',
                      cutoff=CUTOFF, session_limit=1, assessment_id='A1')
        params.update(kwargs)
        with pytest.raises(ValueError, match='usage_assessment_conflict'):
            usage.assess(db, **params)


def test_new_log_version_requires_new_assessment_and_keeps_old(tmp_path):
    db = ready(tmp_path)
    usage.register(db, 'shift-1', FIX / 'usage-scans.jsonl')
    original = usage.assess(db, 'shift-1', 120, 'guaranteed', CUTOFF, 1, 'A1')
    usage.register(db, 'shift-2', FIX / 'usage-scans-multi.jsonl')
    with pytest.raises(ValueError, match='usage_assessment_conflict'):
        usage.assess(db, 'shift-2', 120, 'guaranteed', CUTOFF, 1, 'A1')
    newer = usage.assess(db, 'shift-2', 120, 'guaranteed', CUTOFF, 1, 'A2')
    assert newer['log_id'] == 'shift-2'
    # The old assessment is neither overwritten nor recomputable into the new log.
    assert usage.assess(db, 'shift-1', 120, 'guaranteed', CUTOFF, 1, 'A1') == original
    assert usage.verify(db, 'A1') == [] and usage.verify(db, 'A2') == []
    con = connect(db)
    stored = con.execute('SELECT result FROM usage_assessment WHERE id=?', ('A1',)).fetchone()[0]
    con.close()
    assert json.loads(stored) == original


def test_verify_detects_tampering(tmp_path):
    def assessed(name):
        db = ready(tmp_path / name)
        usage.register(db, 'shift-1', FIX / 'usage-scans.jsonl')
        usage.assess(db, 'shift-1', 120, 'guaranteed', CUTOFF, 1, 'A1')
        return db

    assert usage.verify(assessed('clean'), 'A1') == []

    db = assessed('scan-tamper')
    con = connect(db)
    con.execute("UPDATE usage_scan SET reported_at='2026-05-01T10:01:00Z' WHERE event_id='e1'")
    con.commit(); con.close()
    assert 'usage_scan_table_mismatch' in usage.verify(db, 'A1')

    db = assessed('result-tamper')
    con = connect(db)
    row = con.execute('SELECT result FROM usage_assessment WHERE id=?', ('A1',)).fetchone()[0]
    forged = json.loads(row)
    forged['groups'][0]['guaranteed']['max'] = 1
    con.execute('UPDATE usage_assessment SET result=? WHERE id=?',
                (json.dumps(forged, sort_keys=True), 'A1'))
    con.commit(); con.close()
    assert 'assessment_result_mismatch' in usage.verify(db, 'A1')

    db = assessed('witness-tamper')
    con = connect(db)
    row = con.execute('SELECT result FROM usage_assessment WHERE id=?', ('A1',)).fetchone()[0]
    forged = json.loads(row)
    forged['groups'][0]['guaranteed']['max_witness'] = {'G1': 0, 'G2': 0}
    con.execute('UPDATE usage_assessment SET result=? WHERE id=?',
                (json.dumps(forged, sort_keys=True), 'A1'))
    con.commit(); con.close()
    assert 'assessment_result_mismatch' in usage.verify(db, 'A1')

    db = assessed('limit-tamper')
    con = connect(db)
    con.execute('UPDATE usage_assessment SET session_limit=99 WHERE id=?', ('A1',))
    con.commit(); con.close()
    assert 'assessment_params_tampered' in usage.verify(db, 'A1')

    db = assessed('source-tamper')
    con = connect(db)
    con.execute("UPDATE usage_log SET source=? WHERE id='shift-1'",
                ((FIX / 'usage-scans-multi.jsonl').read_bytes(),))
    con.commit(); con.close()
    problems = usage.verify(db, 'A1')
    assert 'usage_log_source_tampered' in problems


def test_assessments_do_not_feed_retention_or_request_flows(tmp_path):
    db = ready(tmp_path)
    usage.register(db, 'shift-1', FIX / 'usage-scans.jsonl')
    decisions = rules.evaluate(db)
    request = triage(db, 'REQ-U', ['D'], '2099-01-01T00:00:00Z')
    con = connect(db)
    runs_before = con.execute('SELECT count(*) FROM run').fetchone()[0]
    con.close()
    usage.assess(db, 'shift-1', 120, 'guaranteed', CUTOFF, 1, 'A1')
    usage.assess(db, 'shift-1', 120, 'reported', CUTOFF, 1, 'A2')
    con = connect(db)
    assert con.execute('SELECT count(*) FROM run').fetchone()[0] == runs_before
    con.close()
    assert rules.evaluate(db) == decisions
    assert triage(db, 'REQ-U', ['D'], '2099-01-01T00:00:00Z') == request
    assert usage.summary(db, 'shift-1') == {'scans': 4, 'actors': 1, 'devices': 2}


def test_exact_bounds_match_brute_force():
    rng = random.Random(20261120)

    def brute_count(intervals, offsets, gap):
        points = sorted((s + offsets[d], e + offsets[d]) for s, e, d in intervals)
        count, end_so_far = 0, None
        for start, end in points:
            if end_so_far is None or start - end_so_far > gap:
                count += 1
                end_so_far = end
            else:
                end_so_far = max(end_so_far, end)
        return count

    for _ in range(60):
        devices = [f'G{i + 1}' for i in range(rng.choice([2, 3]))]
        intervals = []
        for device in devices:
            at = 0
            for k in range(rng.choice([1, 2])):
                at += rng.randint(0, 20)
                duration = rng.randint(0, 10)
                intervals.append((at, at + duration, device))
                at += duration + rng.randint(0, 5)
        errors = {device: rng.randint(0, 3) for device in devices}
        gap = rng.randint(0, 4)
        ivs = [{'device': d, 'start': s, 'end': e, 'enter': f'{d}{k}e', 'exit': f'{d}{k}x'}
               for k, (s, e, d) in enumerate(intervals)]
        low, low_witness, _, high, high_witness, _ = usage._exact_bounds(ivs, errors, gap)
        grids = [range(-errors[d], errors[d] + 1) for d in devices]
        counts = set()
        for combo in itertools.product(*grids):
            counts.add(brute_count(intervals, dict(zip(devices, combo)), gap))
        assert (low, high) == (min(counts), max(counts))
        for witness, bound in ((low_witness, low), (high_witness, high)):
            assert set(witness) == set(devices)
            assert all(abs(witness[d]) <= errors[d] for d in devices)
            assert brute_count(intervals, witness, gap) == bound


def test_assess_parameter_validation(tmp_path):
    db = ready(tmp_path)
    usage.register(db, 'shift-1', FIX / 'usage-scans.jsonl')
    with pytest.raises(ValueError, match='unknown_usage_log'):
        usage.assess(db, 'nope', 120, 'reported', CUTOFF, 1, 'A')
    with pytest.raises(ValueError, match='bad_clock_contract'):
        usage.assess(db, 'shift-1', 120, 'optimistic', CUTOFF, 1, 'A')
    with pytest.raises(ValueError, match='bad_gap_seconds'):
        usage.assess(db, 'shift-1', -1, 'reported', CUTOFF, 1, 'A')
    with pytest.raises(ValueError, match='bad_session_limit'):
        usage.assess(db, 'shift-1', 120, 'reported', CUTOFF, -1, 'A')
    with pytest.raises(ValueError, match='bad_cutoff'):
        usage.assess(db, 'shift-1', 120, 'reported', '2026-05-02 10:00', 1, 'A')
    with pytest.raises(ValueError, match='bad_assessment_id'):
        usage.assess(db, 'shift-1', 120, 'reported', CUTOFF, 1, '')
    with pytest.raises(ValueError, match='unknown_usage_assessment'):
        usage.verify(db, 'nope')


def test_cli_usage_assess_and_verify(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    db = tmp_path / 'cli.db'
    env = dict(os.environ, PYTHONPATH=str(repo))

    def run(*args):
        return subprocess.run([sys.executable, '-B', '-m', 'retaincase', *args],
                              capture_output=True, text=True, cwd=repo, env=env)

    assert run('init', '--db', str(db), '--config', str(FIX / 'config.json')).returncode == 0
    assert run('load', '--db', str(db), str(FIX / 'events.jsonl')).returncode == 0
    assert run('usage-register', '--db', str(db), '--id', 'shift-1',
               '--source', str(FIX / 'usage-scans.jsonl')).returncode == 0
    result = run('usage-assess', '--db', str(db), '--id', 'CLI-1', '--log', 'shift-1',
                 '--gap', '120', '--contract', 'guaranteed', '--cutoff', CUTOFF, '--limit', '1')
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload['verdict'] == 'indeterminate'
    assert (payload['groups'][0]['guaranteed']['min'], payload['groups'][0]['guaranteed']['max']) == (1, 2)
    checked = run('usage-verify', '--db', str(db), '--id', 'CLI-1')
    assert checked.returncode == 0 and checked.stdout.strip() == '[]'
