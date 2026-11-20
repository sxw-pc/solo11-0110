"""Freeze local access scans for retained subjects and assess access sessions offline.

Session assessments are independent of retention disposition: rules.evaluate,
erasure requests, custody handoffs and recalls never consume these conclusions.

Two clock contracts are supported:
- reported: sessions are counted directly on the reported timeline, answering
  how many access sessions a duty analyst sees on the raw scans.
- guaranteed: every device in one log shares a single unknown constant clock
  offset bounded by the tightest ±error_seconds of its rows; offsets of
  different devices are independent. The assessment reports the exact minimum
  and maximum session count over all feasible offset configurations, each with
  a replayable integer offset witness. Offsets are never chosen per scan and
  the cross-device event order is never frozen in advance.
"""
import hashlib
import json
from pathlib import Path

from .store import connect
from .timeline import instant

ALGORITHM = 'usage-assess-v1'
CONTRACTS = ('reported', 'guaranteed')


def _parse_scans(raw):
    rows = []
    for line in raw.decode('utf-8').splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        event_id, subject, actor, device, action, at, error = (item[k] for k in
            ('event_id', 'subject', 'actor', 'device', 'action', 'reported_at', 'error_seconds'))
        instant(at)
        if not all(isinstance(x, str) and x for x in (event_id, subject, actor, device)) \
                or action not in ('enter', 'exit') or type(error) is not int or error < 0:
            raise ValueError('bad_usage_scan')
        rows.append({'event_id': event_id, 'subject': subject, 'actor': actor,
                     'device': device, 'action': action, 'reported_at': at,
                     'error_seconds': error})
    if not rows or len({r['event_id'] for r in rows}) != len(rows):
        raise ValueError('duplicate_or_empty_usage_scans')
    return rows


def register(db_path, log_id, source_path):
    raw = Path(source_path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if not log_id:
        raise ValueError('bad_usage_log_id')
    scans = _parse_scans(raw)
    db = connect(db_path)
    try:
        with db:
            batch = db.execute('SELECT id FROM batch LIMIT 1').fetchone()
            if not batch:
                raise ValueError('initialize_first')
            old = db.execute('SELECT source_hash FROM usage_log WHERE id=?', (log_id,)).fetchone()
            if old:
                if old['source_hash'] != digest:
                    raise ValueError('usage_log_identity_conflict')
                return digest
            for row in scans:
                if not db.execute('SELECT 1 FROM subject WHERE id=? AND batch_id=?',
                                  (row['subject'], batch['id'])).fetchone():
                    raise ValueError('unknown_usage_subject')
            db.execute('INSERT INTO usage_log VALUES (?,?,?,?)', (log_id, batch['id'], digest, raw))
            db.executemany('INSERT INTO usage_scan VALUES (?,?,?,?,?,?,?,?)',
                           [(log_id, r['event_id'], r['subject'], r['actor'], r['device'],
                             r['action'], r['reported_at'], r['error_seconds']) for r in scans])
            return digest
    finally:
        db.close()


def summary(db_path, log_id):
    """Raw scan counts only; no pairing or clock correction."""
    db = connect(db_path)
    try:
        if not db.execute('SELECT 1 FROM usage_log WHERE id=?', (log_id,)).fetchone():
            raise ValueError('unknown_usage_log')
        scans = db.execute('SELECT count(*) n FROM usage_scan WHERE log_id=?', (log_id,)).fetchone()['n']
        actors = db.execute('SELECT count(DISTINCT actor) n FROM usage_scan WHERE log_id=?',
                            (log_id,)).fetchone()['n']
        devices = db.execute('SELECT count(DISTINCT device) n FROM usage_scan WHERE log_id=?',
                             (log_id,)).fetchone()['n']
        return {'scans': scans, 'actors': actors, 'devices': devices}
    finally:
        db.close()


def _epoch(value):
    return int(instant(value).timestamp())


def _params_hash(log_id, source_hash, gap_seconds, clock_contract, cutoff, session_limit, algorithm):
    body = {'log_id': log_id, 'source_hash': source_hash, 'gap_seconds': gap_seconds,
            'clock_contract': clock_contract, 'cutoff': cutoff, 'session_limit': session_limit,
            'algorithm': algorithm}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode('utf-8')).hexdigest()


def _merge_sessions(intervals, gap_seconds):
    """Merge actual-time intervals; a gap of at most gap_seconds (or overlap) joins.

    Integer seconds throughout; a gap exactly equal to gap_seconds merges."""
    ordered = sorted(intervals, key=lambda iv: (iv['start'], iv['end'], iv['device'],
                                                iv['enter'], iv['exit']))
    sessions = []
    current = None
    for iv in ordered:
        if current is not None and iv['start'] - current['end'] <= gap_seconds:
            current['end'] = max(current['end'], iv['end'])
            current['members'].append(iv)
        else:
            if current is not None:
                sessions.append(current)
            current = {'end': iv['end'], 'members': [iv]}
    if current is not None:
        sessions.append(current)
    return sessions


def _session_members(sessions):
    return [sorted({eid for iv in session['members'] for eid in (iv['enter'], iv['exit'])})
            for session in sessions]


def _shifted(intervals, offsets):
    return [dict(iv, start=iv['start'] + offsets[iv['device']],
                 end=iv['end'] + offsets[iv['device']]) for iv in intervals]


def _pair_group(rows, all_rows, cutoff_epoch):
    """Pair enter/exit scans of one subject+actor group into device access intervals.

    Pairing is per device on reported time, which a shared device offset cannot
    reorder. Any ordering anomaly, duplicate or missing exit yields a concrete
    pending-review reason instead of silently counting zero sessions."""
    intervals = []
    reasons = []
    by_device = {}
    for row in rows:
        by_device.setdefault(row['device'], []).append(row)
    for device in sorted(by_device):
        scans = sorted(by_device[device], key=lambda r: (_epoch(r['reported_at']), r['event_id']))
        open_enter = None
        broken = False
        for scan in scans:
            if scan['action'] == 'enter':
                if open_enter is not None:
                    reasons.append({'code': 'duplicate_enter', 'device': device,
                                    'detail': f"enter {scan['event_id']} reported while enter "
                                              f"{open_enter['event_id']} is still open"})
                    broken = True
                    break
                open_enter = scan
            else:
                if open_enter is None:
                    reasons.append({'code': 'exit_without_enter', 'device': device,
                                    'detail': f"exit {scan['event_id']} has no preceding enter"})
                    broken = True
                    break
                intervals.append({'device': device,
                                  'start': _epoch(open_enter['reported_at']),
                                  'end': _epoch(scan['reported_at']),
                                  'enter': open_enter['event_id'], 'exit': scan['event_id']})
                open_enter = None
        if not broken and open_enter is not None:
            later = sorted(r['event_id'] for r in all_rows
                           if r['device'] == device and r['action'] == 'exit'
                           and _epoch(r['reported_at']) > cutoff_epoch)
            cause = f"exit {later[0]} reported after cutoff" if later else "no exit in log"
            reasons.append({'code': 'unclosed_interval', 'device': device,
                            'detail': f"enter {open_enter['event_id']} unclosed at cutoff: {cause}"})
    return intervals, reasons


def _overlap_reasons(intervals, errors_by_device):
    """Cross-device overlap of one subject+actor is physically impossible.

    Overlap that no feasible pair of device offsets can separate proves an
    impossible error intersection; overlap that offsets could explain is still
    flagged for review rather than silently merged."""
    reasons = []
    for a in range(len(intervals)):
        for b in range(a + 1, len(intervals)):
            x, y = intervals[a], intervals[b]
            if x['device'] == y['device']:
                continue
            if x['start'] < y['end'] and y['start'] < x['end']:
                budget = errors_by_device[x['device']] + errors_by_device[y['device']]
                resolvable = min(x['end'] - y['start'], y['end'] - x['start']) <= budget
                reasons.append({
                    'code': 'cross_device_overlap' if resolvable else 'impossible_error_intersection',
                    'devices': sorted([x['device'], y['device']]),
                    'detail': f"intervals {x['enter']}/{x['exit']} on {x['device']} and "
                              f"{y['enter']}/{y['exit']} on {y['device']} overlap in reported time"
                              + ('' if resolvable else ' beyond any feasible clock error')})
    return reasons


def _feasible(count, constraints):
    """Bellman-Ford over difference constraints x[v] - x[u] <= c.

    Returns integer feasible potentials or None when a negative cycle makes the
    system infeasible. Integer difference constraints are feasible over the
    integers exactly when feasible over the rationals."""
    dist = [0] * count
    for _ in range(count):
        updated = False
        for u, v, c in constraints:
            if dist[v] > dist[u] + c:
                dist[v] = dist[u] + c
                updated = True
        if not updated:
            return dist
    for u, v, c in constraints:
        if dist[v] > dist[u] + c:
            return None
    return dist


def _exact_bounds(intervals, errors_by_device, gap_seconds):
    """Exact min/max session counts over all feasible per-device clock offsets.

    Same-device relations are offset-invariant; a cross-device interval pair is
    adjacent exactly when the device offset difference lies in a computed
    integer window. The session count is therefore constant on every cell of
    the arrangement of those windows in offset-difference space. Enumerating
    every feasible cell (complete, no sampling or fixed grid) and evaluating
    one integer witness per cell yields the exact extrema. Witnesses are
    shifted back into the declared per-device ±error box, which the
    shiftability constraints guarantee is always possible."""
    devices = sorted({iv['device'] for iv in intervals})
    if len(devices) == 1:
        sessions = _merge_sessions(intervals, gap_seconds)
        members = _session_members(sessions)
        witness = {devices[0]: 0}
        return len(sessions), witness, members, len(sessions), witness, members
    index = {device: i for i, device in enumerate(devices)}
    count = len(devices)
    span = [errors_by_device[device] for device in devices]
    pairs = sorted(((i, j) for i in range(count) for j in range(i + 1, count)),
                   key=lambda p: (p[1], p[0]))
    windows = {p: [] for p in pairs}
    for a in range(len(intervals)):
        for b in range(a + 1, len(intervals)):
            x, y = intervals[a], intervals[b]
            if x['device'] == y['device']:
                continue
            i, j = index[x['device']], index[y['device']]
            if i > j:
                x, y, i, j = y, x, j, i
            windows[(i, j)].append((x['start'] - y['end'] - gap_seconds,
                                    x['end'] - y['start'] + gap_seconds))
    segments = {}
    for i, j in pairs:
        lo, hi = -(span[i] + span[j]), span[i] + span[j]
        cuts = {lo, hi + 1}
        for low, high in windows[(i, j)]:
            cuts.add(min(max(low, lo), hi + 1))
            cuts.add(max(min(high + 1, hi + 1), lo))
        points = sorted(cuts)
        segments[(i, j)] = [(points[k], points[k + 1] - 1) for k in range(len(points) - 1)]
    base = [(j, i, span[i] + span[j]) for i in range(count) for j in range(count) if i != j]
    best_min = best_max = None

    def visit(offsets):
        nonlocal best_min, best_max
        shift = max(-span[i] - offsets[i] for i in range(count))
        witness = {devices[i]: offsets[i] + shift for i in range(count)}
        sessions = _merge_sessions(_shifted(intervals, witness), gap_seconds)
        outcome = (len(sessions), witness, _session_members(sessions))
        if best_min is None or outcome[0] < best_min[0]:
            best_min = outcome
        if best_max is None or outcome[0] > best_max[0]:
            best_max = outcome

    def recurse(k, constraints):
        if k == len(pairs):
            rep = _feasible(count, constraints)
            if rep is not None:
                visit(rep)
            return
        i, j = pairs[k]
        for lo, hi in segments[pairs[k]]:
            nxt = constraints + [(i, j, hi), (j, i, -lo)]
            if _feasible(count, nxt) is not None:
                recurse(k + 1, nxt)

    recurse(0, list(base))
    return best_min + best_max


def _compute(scans, log_id, source_hash, gap_seconds, clock_contract, cutoff,
             session_limit, assessment_id):
    cutoff_epoch = _epoch(cutoff)
    errors_by_device = {}
    for row in scans:
        device = row['device']
        errors_by_device[device] = min(row['error_seconds'],
                                       errors_by_device.get(device, row['error_seconds']))
    counted = [row for row in scans if _epoch(row['reported_at']) <= cutoff_epoch]
    grouped, everything = {}, {}
    for row in scans:
        everything.setdefault((row['subject'], row['actor']), []).append(row)
        if _epoch(row['reported_at']) <= cutoff_epoch:
            grouped.setdefault((row['subject'], row['actor']), []).append(row)
    groups = []
    for subject, actor in sorted(grouped):
        intervals, reasons = _pair_group(grouped[(subject, actor)],
                                         everything[(subject, actor)], cutoff_epoch)
        if not reasons:
            reasons = _overlap_reasons(intervals, errors_by_device)
        reasons = [dict(reason, subject=subject, actor=actor) for reason in reasons]
        group = {'subject': subject, 'actor': actor, 'contract': clock_contract,
                 'status': 'ok', 'reasons': reasons,
                 'reported': None, 'guaranteed': None, 'verdict': None}
        if reasons:
            group['status'] = 'pending_review'
            group['verdict'] = 'pending_review'
        elif clock_contract == 'reported':
            sessions = _merge_sessions(intervals, gap_seconds)
            group['reported'] = {'sessions': len(sessions),
                                 'members': _session_members(sessions)}
            group['verdict'] = 'pass' if len(sessions) <= session_limit else 'fail'
        else:
            low, low_witness, low_members, high, high_witness, high_members = _exact_bounds(
                intervals, errors_by_device, gap_seconds)
            group['guaranteed'] = {'min': low, 'max': high,
                                   'min_witness': low_witness, 'max_witness': high_witness,
                                   'min_sessions': low_members, 'max_sessions': high_members}
            group['verdict'] = 'pass' if high <= session_limit else (
                'fail' if low > session_limit else 'indeterminate')
        groups.append(group)
    verdicts = {group['verdict'] for group in groups}
    if 'fail' in verdicts:
        verdict = 'fail'
    elif 'pending_review' in verdicts:
        verdict = 'pending_review'
    elif 'indeterminate' in verdicts:
        verdict = 'indeterminate'
    else:
        verdict = 'pass'
    return {
        'assessment_id': assessment_id,
        'log_id': log_id,
        'source_hash': source_hash,
        'algorithm': ALGORITHM,
        'params': {'gap_seconds': gap_seconds, 'clock_contract': clock_contract,
                   'cutoff': cutoff, 'session_limit': session_limit},
        'status': 'ok' if all(group['status'] == 'ok' for group in groups) else 'pending_review',
        'verdict': verdict,
        'groups': groups,
        'input_summary': {'scans_total': len(scans), 'scans_counted': len(counted),
                          'subjects': len({row['subject'] for row in counted}),
                          'actors': len({row['actor'] for row in counted}),
                          'devices': len({row['device'] for row in counted}),
                          'groups': len(groups)},
    }


def assess(db_path, log_id, gap_seconds, clock_contract, cutoff, session_limit, assessment_id):
    """Freeze a session assessment bound to a frozen log, parameters and algorithm.

    The same assessment_id with the same parameters replays the stored result;
    different parameters conflict. A new log version needs a new assessment_id;
    stored assessments are never overwritten by new scans or policies."""
    if not isinstance(assessment_id, str) or not assessment_id:
        raise ValueError('bad_assessment_id')
    if type(gap_seconds) is not int or gap_seconds < 0:
        raise ValueError('bad_gap_seconds')
    if type(session_limit) is not int or session_limit < 0:
        raise ValueError('bad_session_limit')
    if clock_contract not in CONTRACTS:
        raise ValueError('bad_clock_contract')
    try:
        cutoff_iso = instant(cutoff).isoformat()
    except (AttributeError, TypeError, ValueError):
        raise ValueError('bad_cutoff') from None
    db = connect(db_path)
    try:
        log = db.execute('SELECT * FROM usage_log WHERE id=?', (log_id,)).fetchone()
        if not log:
            raise ValueError('unknown_usage_log')
        if hashlib.sha256(log['source']).hexdigest() != log['source_hash']:
            raise ValueError('usage_log_source_tampered')
        params_hash = _params_hash(log_id, log['source_hash'], gap_seconds, clock_contract,
                                   cutoff_iso, session_limit, ALGORITHM)
        old = db.execute('SELECT params_hash, result FROM usage_assessment WHERE id=?',
                         (assessment_id,)).fetchone()
        if old:
            if old['params_hash'] != params_hash:
                raise ValueError('usage_assessment_conflict')
            return json.loads(old['result'])
        result = _compute(_parse_scans(log['source']), log_id, log['source_hash'], gap_seconds,
                          clock_contract, cutoff_iso, session_limit, assessment_id)
        with db:
            db.execute('INSERT INTO usage_assessment VALUES (?,?,?,?,?,?,?,?,?,?)',
                       (assessment_id, log_id, log['source_hash'], gap_seconds, clock_contract,
                        cutoff_iso, session_limit, ALGORITHM, params_hash,
                        json.dumps(result, ensure_ascii=False, sort_keys=True)))
        return result
    finally:
        db.close()


def _replay_witness(intervals, witness, gap_seconds, expected):
    sessions = _merge_sessions(_shifted(intervals, witness), gap_seconds)
    return len(sessions) == expected


def verify(db_path, assessment_id):
    """Re-pair from the frozen raw scans and re-check witnesses, extrema and verdict.

    Tampering with the scan table, the frozen source, the parameters, the stored
    result or an offset witness makes verification fail."""
    db = connect(db_path)
    try:
        row = db.execute('SELECT * FROM usage_assessment WHERE id=?', (assessment_id,)).fetchone()
        if not row:
            raise ValueError('unknown_usage_assessment')
        problems = []
        log = db.execute('SELECT * FROM usage_log WHERE id=?', (row['log_id'],)).fetchone()
        if not log:
            return ['usage_log_missing']
        digest = hashlib.sha256(log['source']).hexdigest()
        if digest != log['source_hash']:
            problems.append('usage_log_source_tampered')
        if digest != row['source_hash']:
            problems.append('assessment_source_mismatch')
        if row['algorithm'] != ALGORITHM:
            problems.append('algorithm_mismatch')
        if _params_hash(row['log_id'], row['source_hash'], row['gap_seconds'], row['clock_contract'],
                        row['cutoff'], row['session_limit'], row['algorithm']) != row['params_hash']:
            problems.append('assessment_params_tampered')
        try:
            scans = _parse_scans(log['source'])
        except ValueError:
            return problems + ['usage_log_source_unparseable']
        table = db.execute('SELECT event_id,subject,actor,device,action,reported_at,error_seconds '
                           'FROM usage_scan WHERE log_id=? ORDER BY event_id',
                           (row['log_id'],)).fetchall()
        frozen = sorted((r['event_id'], r['subject'], r['actor'], r['device'], r['action'],
                         r['reported_at'], r['error_seconds']) for r in scans)
        if [tuple(r) for r in table] != frozen:
            problems.append('usage_scan_table_mismatch')
        stored = json.loads(row['result'])
        fresh = _compute(scans, row['log_id'], row['source_hash'], row['gap_seconds'],
                         row['clock_contract'], row['cutoff'], row['session_limit'], row['id'])
        if fresh != stored:
            problems.append('assessment_result_mismatch')
            return problems
        errors_by_device = {}
        for r in scans:
            errors_by_device[r['device']] = min(r['error_seconds'],
                                                errors_by_device.get(r['device'], r['error_seconds']))
        cutoff_epoch = _epoch(row['cutoff'])
        for group in stored['groups']:
            payload = group['guaranteed']
            if group['status'] != 'ok' or not payload:
                continue
            members = [r for r in scans
                       if r['subject'] == group['subject'] and r['actor'] == group['actor']]
            intervals, _ = _pair_group(
                [r for r in members if _epoch(r['reported_at']) <= cutoff_epoch],
                members, cutoff_epoch)
            for bound in ('min', 'max'):
                witness = payload[f'{bound}_witness']
                valid = isinstance(witness, dict) and witness and all(
                    type(offset) is int and device in errors_by_device
                    and abs(offset) <= errors_by_device[device]
                    for device, offset in witness.items())
                if not valid or not _replay_witness(intervals, witness, row['gap_seconds'],
                                                    payload[bound]):
                    problems.append(f"witness_invalid:{group['subject']}/{group['actor']}:{bound}")
        return problems
    finally:
        db.close()
