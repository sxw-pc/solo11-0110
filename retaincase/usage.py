"""Freeze local access scans and derive device-access session statistics.

The scan log is frozen byte-for-byte by :func:`register`; session inference
lives here and never feeds the retention rule engine, erasure requests,
custody handoff or recall flows.

Two frozen accounting contracts share one pairing stage:

* ``reported``  — answer what the duty analyst sees on the raw reported
  timeline, using ``reported_at`` directly.
* ``guaranteed`` — every scan of one device inside one log shares a single
  unknown constant integer clock offset that must satisfy every scan's
  ``±error_seconds``; device offsets are independent.  We return the exact
  minimum/maximum reachable session counts over the full feasible offset
  space, each with a replayable offset witness.  No fixed time grid, random
  sampling or per-scan drift is used.
"""
import hashlib
import json
from datetime import timezone
from pathlib import Path

from .store import connect
from .timeline import instant

ALGORITHM_VERSION = 'usage-assess-1.0.0'

SCHEMA = """
CREATE TABLE IF NOT EXISTS usage_assessment(
 id TEXT PRIMARY KEY, log_id TEXT NOT NULL REFERENCES usage_log(id),
 batch_id TEXT NOT NULL REFERENCES batch(id), source_hash TEXT NOT NULL,
 clock_contract TEXT NOT NULL CHECK(clock_contract IN ('reported','guaranteed')),
 gap_seconds INTEGER NOT NULL, cutoff TEXT NOT NULL, session_limit INTEGER NOT NULL,
 param_hash TEXT NOT NULL, algorithm_version TEXT NOT NULL, state TEXT NOT NULL,
 body TEXT NOT NULL, UNIQUE(log_id,id));
"""


# --------------------------------------------------------------------------- #
# Frozen log registration and raw counts (unchanged behaviour)
# --------------------------------------------------------------------------- #
def register(db_path, log_id, source_path):
    raw = Path(source_path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if not log_id:
        raise ValueError('bad_usage_log_id')
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
        rows.append((log_id, event_id, subject, actor, device, action, at, error))
    if not rows or len({r[1] for r in rows}) != len(rows):
        raise ValueError('duplicate_or_empty_usage_scans')
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
            for row in rows:
                if not db.execute('SELECT 1 FROM subject WHERE id=? AND batch_id=?',
                                  (row[2], batch['id'])).fetchone():
                    raise ValueError('unknown_usage_subject')
            db.execute('INSERT INTO usage_log VALUES (?,?,?,?)', (log_id, batch['id'], digest, raw))
            db.executemany('INSERT INTO usage_scan VALUES (?,?,?,?,?,?,?,?)', rows)
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


# --------------------------------------------------------------------------- #
# Pure engine: parsing, pairing, reported sessions, guaranteed exact extrema
# --------------------------------------------------------------------------- #
def _epoch(value):
    return int(instant(value).astimezone(timezone.utc).timestamp())


def _load_scans(db, log_id):
    if not db.execute('SELECT 1 FROM usage_log WHERE id=?', (log_id,)).fetchone():
        raise ValueError('unknown_usage_log')
    scans = []
    for r in db.execute('SELECT * FROM usage_scan WHERE log_id=? ORDER BY event_id', (log_id,)):
        d = dict(r)
        d['reported_epoch'] = _epoch(d['reported_at'])
        scans.append(d)
    return scans


def _pair_scans(scans, cutoff_epoch):
    """Pair enter/exit scans per subject+actor+device from the frozen rows.

    Structural pairing problems are fatal and reported with explicit reason
    codes; a cut-off open interval is a non-fatal pending-review finding.
    """
    problems = []
    counted = [s for s in scans if s['reported_epoch'] <= cutoff_epoch]
    excluded = [s['event_id'] for s in scans if s['reported_epoch'] > cutoff_epoch]
    groups = {}
    for s in counted:
        groups.setdefault((s['subject'], s['actor'], s['device']), []).append(s)

    intervals = []          # closed, well-formed device access intervals
    open_pairs = []         # enter whose exit falls after the cutoff (pending)
    for (subject, actor, device), rows in sorted(groups.items()):
        rows = sorted(rows, key=lambda s: (s['reported_epoch'], s['event_id']))
        depth = 0
        enter_row = None
        for s in rows:
            if s['action'] == 'enter':
                if depth:
                    problems.append({'code': 'duplicate_enter_without_exit',
                                     'device': device, 'subject': subject, 'actor': actor,
                                     'event_id': s['event_id']})
                else:
                    enter_row = s
                depth += 1
            else:  # exit
                if depth == 0:
                    problems.append({'code': 'exit_without_enter',
                                     'device': device, 'subject': subject, 'actor': actor,
                                     'event_id': s['event_id']})
                    continue
                if enter_row['reported_epoch'] >= s['reported_epoch']:
                    problems.append({'code': 'enter_not_before_exit',
                                     'device': device, 'subject': subject, 'actor': actor,
                                     'event_ids': [enter_row['event_id'], s['event_id']]})
                else:
                    intervals.append({'subject': subject, 'actor': actor, 'device': device,
                                      'enter_id': enter_row['event_id'], 'exit_id': s['event_id'],
                                      'enter_epoch': enter_row['reported_epoch'],
                                      'exit_epoch': s['reported_epoch'],
                                      'error_seconds': max(enter_row['error_seconds'],
                                                           s['error_seconds'])})
                depth -= 1
                enter_row = None if depth == 0 else enter_row
        if depth > 0 and enter_row is not None:
            # An enter is open here either structurally or because its exit
            # scan is beyond the cutoff; disambiguate with the full log.
            later_exit = [x['event_id'] for x in scans
                          if x['subject'] == subject and x['actor'] == actor
                          and x['device'] == device and x['action'] == 'exit'
                          and x['reported_epoch'] > cutoff_epoch]
            if later_exit:
                open_pairs.append({'subject': subject, 'actor': actor, 'device': device,
                                   'enter_id': enter_row['event_id'],
                                   'enter_epoch': enter_row['reported_epoch'],
                                   'pending_exit_ids': later_exit})
            else:
                problems.append({'code': 'missing_exit',
                                 'device': device, 'subject': subject, 'actor': actor,
                                 'event_id': enter_row['event_id']})
    return counted, excluded, intervals, open_pairs, problems


def _merge_intervals(intervals, gap_seconds):
    """Merge intervals of one subject+actor; touching gaps of exactly
    ``gap_seconds`` still merge (boundary is inclusive)."""
    ordered = sorted(intervals, key=lambda iv: (iv['start'], iv['end'], iv['device'],
                                                iv['enter_id'], iv['exit_id']))
    sessions = []
    for iv in ordered:
        if sessions and iv['start'] <= sessions[-1]['end'] + gap_seconds:
            cur = sessions[-1]
            cur['end'] = max(cur['end'], iv['end'])
            cur['members'].append(iv)
        else:
            sessions.append({'start': iv['start'], 'end': iv['end'], 'members': [iv]})
    return sessions


def _reported_sessions(intervals, open_pairs, gap_seconds):
    by_pair = {}
    for iv in intervals:
        by_pair.setdefault((iv['subject'], iv['actor']), []).append(iv)
    result = {}
    for key in sorted(by_pair):
        placed = [{'start': iv['enter_epoch'], 'end': iv['exit_epoch'], 'device': iv['device'],
                   'enter_id': iv['enter_id'], 'exit_id': iv['exit_id'],
                   'error_seconds': iv['error_seconds']} for iv in by_pair[key]]
        sessions = _merge_intervals(placed, gap_seconds)
        result['|'.join(key)] = {
            'sessions': [{'member_scan_ids': sorted(eid for m in s['members']
                                                    for eid in (m['enter_id'], m['exit_id'])),
                          'interval_scans': [{'device': m['device'],
                                              'enter_id': m['enter_id'],
                                              'exit_id': m['exit_id']} for m in s['members']]}
                         for s in sessions]}
    for op in open_pairs:
        key = '|'.join((op['subject'], op['actor']))
        result.setdefault(key, {'sessions': []})
        result[key].setdefault('open_intervals', []).append(
            {'device': op['device'], 'enter_id': op['enter_id'],
             'pending_exit_ids': op['pending_exit_ids']})
    return result


def _reported_overlap_problems(intervals):
    """Same actor cannot physically be on two devices at the same instant."""
    problems = []
    by_pair = {}
    for iv in intervals:
        by_pair.setdefault((iv['subject'], iv['actor']), []).append(iv)
    for key, ivs in sorted(by_pair.items()):
        ivs = sorted(ivs, key=lambda iv: (iv['enter_epoch'], iv['exit_epoch'], iv['device']))
        for i in range(len(ivs)):
            for j in range(i + 1, len(ivs)):
                a, b = ivs[i], ivs[j]
                if a['device'] == b['device']:
                    continue
                # Touching at one instant is a device handover, not overlap.
                if b['enter_epoch'] < a['exit_epoch'] and a['enter_epoch'] < b['exit_epoch']:
                    problems.append({'code': 'cross_device_overlap_reported',
                                     'subject': key[0], 'actor': key[1],
                                     'devices': sorted((a['device'], b['device'])),
                                     'event_ids': sorted((a['enter_id'], a['exit_id'],
                                                          b['enter_id'], b['exit_id']))})
    return problems


def _device_domains(counted):
    """One shared constant offset per device: intersection of ±error_seconds."""
    bounds = {}
    for s in counted:
        lo, hi = bounds.get(s['device'], (-s['error_seconds'], s['error_seconds']))
        bounds[s['device']] = (max(lo, -s['error_seconds']), min(hi, s['error_seconds']))
    domains = {}
    for device, (lo, hi) in sorted(bounds.items()):
        if lo > hi:
            domains[device] = None
        else:
            domains[device] = {'min_offset': lo, 'max_offset': hi}
    return domains


def _guaranteed_unavoidable_overlap(intervals, domains):
    """Check whether two devices of one actor overlap under every feasible
    offset assignment; if so the joint feasible offset space is empty."""
    problems = []
    by_pair = {}
    for iv in intervals:
        by_pair.setdefault((iv['subject'], iv['actor']), []).append(iv)
    for key, ivs in sorted(by_pair.items()):
        for i in range(len(ivs)):
            for j in range(i + 1, len(ivs)):
                a, b = ivs[i], ivs[j]
                if a['device'] == b['device']:
                    continue
                da, db_ = domains[a['device']], domains[b['device']]
                if da is None or db_ is None:
                    continue
                # Strict overlap is avoidable iff some feasible offsets put
                # one interval fully before the other (touching allowed):
                # A before B needs exit_A+o_A <= enter_B+o_B for some offsets,
                # feasible when exit_A+min_A <= enter_B+max_B (and symmetric).
                can_order_ab = (a['exit_epoch'] + da['min_offset']
                                <= b['enter_epoch'] + db_['max_offset'])
                can_order_ba = (b['exit_epoch'] + db_['min_offset']
                                <= a['enter_epoch'] + da['max_offset'])
                if not can_order_ab and not can_order_ba:
                    problems.append({'code': 'impossible_offset_intersection',
                                     'subject': key[0], 'actor': key[1],
                                     'devices': sorted((a['device'], b['device'])),
                                     'event_ids': sorted((a['enter_id'], a['exit_id'],
                                                          b['enter_id'], b['exit_id']))})
    return problems


def _session_count_under_offsets(intervals, gap_seconds, offsets):
    """Replay one full offset assignment and return per-pair sessions/counts."""
    shifted = []
    for iv in intervals:
        o = offsets[iv['device']]
        shifted.append({'start': iv['enter_epoch'] + o, 'end': iv['exit_epoch'] + o,
                        'device': iv['device'], 'enter_id': iv['enter_id'],
                        'exit_id': iv['exit_id'], 'subject': iv['subject'],
                        'actor': iv['actor']})
    by_pair = {}
    for iv in shifted:
        by_pair.setdefault((iv['subject'], iv['actor']), []).append(iv)
    pair_sessions = {}
    for key in sorted(by_pair):
        sessions = _merge_intervals(by_pair[key], gap_seconds)
        pair_sessions['|'.join(key)] = {
            'count': len(sessions),
            'sessions': [{'member_scan_ids': sorted(eid for m in s['members']
                                                    for eid in (m['enter_id'], m['exit_id'])),
                          'interval_scans': [{'device': m['device'],
                                              'enter_id': m['enter_id'],
                                              'exit_id': m['exit_id']} for m in s['members']]}
                         for s in sessions]}
    total = sum(v['count'] for v in pair_sessions.values())
    return total, pair_sessions


def _guaranteed_extrema(intervals, domains, gap_seconds):
    """Exact min/max session counts over the complete feasible offset space.

    Offsets are integer seconds and each device owns one shared constant
    offset.  The session count changes only when an interval endpoint of one
    device crosses an endpoint (or gap-shifted endpoint) of another device's
    interval of the same subject+actor.  Every such change is an integer
    hyperplane ``offset_q - offset_p = endpoint_p - endpoint_q``; together
    with the unary domain bounds they form a hyperplane arrangement whose
    open cells have a constant session count.

    For each device we collect the univariate boundary integers of every
    hyperplane mentioning it (and one integer neighbour on each side, so the
    cell on every side has a representative), clipped to its domain.  Any
    non-empty integer cell contains a point whose every coordinate is one of
    those representatives, so the Cartesian product covers every attainable
    value of the count; taking min/max over it is therefore exact.  The cost
    depends on the number of intervals, never on the width of
    ``error_seconds`` — hours-wide error windows cost the same as zero-width.
    """
    devices = sorted(d for d in domains if domains[d] is not None)
    used = sorted({iv['device'] for iv in intervals})
    if not used:
        return {'device_offset_domains': {d: domains[d] for d in devices},
                'min_total_sessions': 0, 'max_total_sessions': 0,
                'min_witness': {'total_sessions': 0,
                                'offset_witness': {d: domains[d]['min_offset'] for d in devices},
                                'pair_sessions': {}},
                'max_witness': {'total_sessions': 0,
                                'offset_witness': {d: domains[d]['min_offset'] for d in devices},
                                'pair_sessions': {}},
                'pairs': {}}
    chain = [d for d in devices if d in used]
    for d in devices:
        if d not in chain:
            chain.append(d)

    by_device = {}
    for iv in intervals:
        by_device.setdefault(iv['device'], []).append(iv)

    # Per-device candidate offsets: domain bounds plus, for every hyperplane
    # involving this device, the boundary integer and both integer neighbours.
    candidates = {}
    for q in chain:
        dom = domains[q]
        vals = {dom['min_offset'], dom['max_offset']}
        for p in chain:
            if p == q:
                continue
            for a in by_device.get(p, ()):
                for b in by_device.get(q, ()):
                    if (a['subject'], a['actor']) != (b['subject'], b['actor']):
                        continue
                    for ep_a in (a['enter_epoch'], a['exit_epoch'],
                                 a['enter_epoch'] - gap_seconds,
                                 a['exit_epoch'] - gap_seconds):
                        for ep_b in (b['enter_epoch'], b['exit_epoch'],
                                     b['enter_epoch'] - gap_seconds,
                                     b['exit_epoch'] - gap_seconds):
                            # x_q - x_p == ep_a - ep_b  =>  x_q = x_p + k.
                            k = ep_a - ep_b
                            # x_p itself ranges over p's domain, so the
                            # boundary values x_p+k span an interval; take its
                            # extremes (and neighbours) rather than every point.
                            dp = domains[p]
                            for base in (dp['min_offset'], dp['max_offset']):
                                for shift in (-1, 0, 1):
                                    vals.add(base + k + shift)
        candidates[q] = sorted(x for x in vals
                               if dom['min_offset'] <= x <= dom['max_offset'])

    best_min = None
    best_max = None
    seen = set()
    assignment = {}

    def evaluate_leaf():
        nonlocal best_min, best_max
        key = tuple(assignment[d] for d in chain)
        if key in seen:
            return
        seen.add(key)
        total, pair_sessions = _session_count_under_offsets(
            intervals, gap_seconds, dict(assignment))
        witness = dict(sorted(assignment.items()))
        if best_min is None or total < best_min['total_sessions']:
            best_min = {'total_sessions': total, 'offset_witness': witness,
                        'pair_sessions': pair_sessions}
        if best_max is None or total > best_max['total_sessions']:
            best_max = {'total_sessions': total, 'offset_witness': witness,
                        'pair_sessions': pair_sessions}

    def dfs(index):
        if index == len(chain):
            evaluate_leaf()
            return
        q = chain[index]
        for x in candidates[q]:
            assignment[q] = x
            dfs(index + 1)
        assignment.pop(q, None)

    dfs(0)

    # Per subject+actor exact extrema, each with its own replayable witness.
    pair_keys = sorted({(iv['subject'], iv['actor']) for iv in intervals})
    pairs = {}
    for key in pair_keys:
        label = '|'.join(key)
        pairs[label] = {
            'min_sessions': best_min['pair_sessions'][label]['count'],
            'min_offset_witness': best_min['offset_witness'],
            'min_sessions_detail': best_min['pair_sessions'][label]['sessions'],
            'max_sessions': best_max['pair_sessions'][label]['count'],
            'max_offset_witness': best_max['offset_witness'],
            'max_sessions_detail': best_max['pair_sessions'][label]['sessions']}
    return {
        'device_offset_domains': {d: domains[d] for d in devices},
        'min_total_sessions': best_min['total_sessions'],
        'max_total_sessions': best_max['total_sessions'],
        'min_witness': best_min,
        'max_witness': best_max,
        'pairs': pairs}


def _verdict_reported(count, session_limit, has_open):
    if has_open:
        return 'indeterminate'
    if count <= session_limit:
        return 'within_limit'
    return 'limit_exceeded'


def _verdict_guaranteed(lo, hi, session_limit):
    if hi <= session_limit:
        return 'within_limit'
    if lo > session_limit:
        return 'limit_exceeded'
    return 'indeterminate'


def run_engine(scans, gap_seconds, clock_contract, cutoff_epoch, session_limit):
    """Pure computation over parsed frozen scan rows; reused by verify."""
    counted, excluded, intervals, open_pairs, pair_problems = _pair_scans(scans, cutoff_epoch)
    domains = _device_domains(counted)
    empty_domains = [d for d, dom in domains.items() if dom is None]
    problems = list(pair_problems)
    for d in empty_domains:
        problems.append({'code': 'empty_device_offset_domain', 'device': d})

    input_summary = {
        'scan_count': len(scans),
        'counted_scan_count': len(counted),
        'excluded_after_cutoff_event_ids': excluded,
        'subjects': sorted({s['subject'] for s in counted}),
        'actors': sorted({s['actor'] for s in counted}),
        'devices': sorted({s['device'] for s in counted})}

    if problems:
        return {'state': '待核', 'input_summary': input_summary, 'problems': problems,
                'paired_intervals': [], 'open_intervals': open_pairs,
                'clock_contract': clock_contract, 'result': None}

    paired_detail = [{'subject': iv['subject'], 'actor': iv['actor'], 'device': iv['device'],
                      'enter_id': iv['enter_id'], 'exit_id': iv['exit_id'],
                      'enter_reported_at': next(s['reported_at'] for s in counted
                                                if s['event_id'] == iv['enter_id']),
                      'exit_reported_at': next(s['reported_at'] for s in counted
                                               if s['event_id'] == iv['exit_id'])}
                     for iv in sorted(intervals, key=lambda iv: (iv['subject'], iv['actor'],
                                                                 iv['device'], iv['enter_id']))]

    if clock_contract == 'reported':
        overlap = _reported_overlap_problems(intervals)
        if overlap:
            return {'state': '待核', 'input_summary': input_summary, 'problems': overlap,
                    'paired_intervals': paired_detail, 'open_intervals': open_pairs,
                    'clock_contract': clock_contract, 'result': None}
        reported = _reported_sessions(intervals, open_pairs, gap_seconds)
        pair_results = {}
        for label, data in sorted(reported.items()):
            count = len(data['sessions'])
            pair_results[label] = {
                'session_count': count,
                'sessions': data['sessions'],
                'open_intervals': data.get('open_intervals', []),
                'verdict': _verdict_reported(count, session_limit,
                                             bool(data.get('open_intervals')))}
        total = sum(v['session_count'] for v in pair_results.values())
        overall = (_verdict_reported(total, session_limit, bool(open_pairs))
                   if pair_results else 'indeterminate')
        state = '待核' if open_pairs else '已判定'
        result = {'contract': 'reported', 'total_sessions': total,
                  'pairs': pair_results, 'overall_verdict': overall}
        return {'state': state, 'input_summary': input_summary, 'problems': [],
                'paired_intervals': paired_detail, 'open_intervals': open_pairs,
                'clock_contract': clock_contract, 'result': result}

    # guaranteed
    impossible = _guaranteed_unavoidable_overlap(intervals, domains)
    if impossible:
        return {'state': '待核', 'input_summary': input_summary, 'problems': impossible,
                'paired_intervals': paired_detail, 'open_intervals': open_pairs,
                'clock_contract': clock_contract, 'result': None}
    extrema = _guaranteed_extrema(intervals, domains, gap_seconds)
    pair_results = {}
    open_labels = {'|'.join((op['subject'], op['actor'])) for op in open_pairs}
    for label, data in sorted(extrema['pairs'].items()):
        pair_results[label] = {
            'min_sessions': data['min_sessions'], 'max_sessions': data['max_sessions'],
            'min_offset_witness': data['min_offset_witness'],
            'max_offset_witness': data['max_offset_witness'],
            'min_sessions_detail': data['min_sessions_detail'],
            'max_sessions_detail': data['max_sessions_detail'],
            'open_intervals': [op for op in open_pairs
                               if '|'.join((op['subject'], op['actor'])) == label],
            'verdict': ('indeterminate' if label in open_labels
                        else _verdict_guaranteed(data['min_sessions'],
                                                 data['max_sessions'], session_limit))}
    # A subject+actor whose only in-window evidence is a cut-off enter has no
    # closed interval but still has to appear as pending, not silently vanish.
    for label in sorted(open_labels):
        if label not in pair_results:
            pair_results[label] = {
                'min_sessions': None, 'max_sessions': None,
                'min_offset_witness': None, 'max_offset_witness': None,
                'min_sessions_detail': [], 'max_sessions_detail': [],
                'open_intervals': [op for op in open_pairs
                                   if '|'.join((op['subject'], op['actor'])) == label],
                'verdict': 'indeterminate'}
    overall = ('indeterminate' if open_pairs
               else _verdict_guaranteed(extrema['min_total_sessions'],
                                        extrema['max_total_sessions'], session_limit))
    result = {'contract': 'guaranteed',
              'min_total_sessions': extrema['min_total_sessions'],
              'max_total_sessions': extrema['max_total_sessions'],
              'device_offset_domains': extrema['device_offset_domains'],
              'min_witness': extrema['min_witness'],
              'max_witness': extrema['max_witness'],
              'pairs': pair_results, 'overall_verdict': overall}
    state = '待核' if open_pairs else '已判定'
    if open_pairs:
        result['open_intervals'] = open_pairs
    return {'state': state, 'input_summary': input_summary, 'problems': [],
            'paired_intervals': paired_detail, 'open_intervals': open_pairs,
            'clock_contract': clock_contract, 'result': result}


def _validate_params(gap_seconds, clock_contract, cutoff_text, session_limit):
    if type(gap_seconds) is not int or gap_seconds < 0:
        raise ValueError('bad_gap_seconds')
    if clock_contract not in ('reported', 'guaranteed'):
        raise ValueError('bad_clock_contract')
    if type(session_limit) is not int or session_limit < 0:
        raise ValueError('bad_session_limit')
    cutoff_epoch = _epoch(cutoff_text)
    return cutoff_epoch


def _param_digest(log_id, source_hash, gap_seconds, clock_contract, cutoff_text,
                  session_limit):
    payload = [ALGORITHM_VERSION, log_id, source_hash, clock_contract, gap_seconds,
               instant(cutoff_text).astimezone(timezone.utc).isoformat(), session_limit]
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False)
                          .encode('utf-8')).hexdigest()


# --------------------------------------------------------------------------- #
# Persisted assessments with frozen parameter/version binding
# --------------------------------------------------------------------------- #
def assess(db_path, log_id, gap_seconds, clock_contract, cutoff, session_limit,
           assessment_id):
    if not assessment_id:
        raise ValueError('bad_assessment_id')
    cutoff_epoch = _validate_params(gap_seconds, clock_contract, cutoff, session_limit)
    db = connect(db_path)
    db.executescript(SCHEMA)
    try:
        log = db.execute('SELECT * FROM usage_log WHERE id=?', (log_id,)).fetchone()
        if not log:
            raise ValueError('unknown_usage_log')
        param_hash = _param_digest(log_id, log['source_hash'], gap_seconds,
                                   clock_contract, cutoff, session_limit)
        old = db.execute('SELECT * FROM usage_assessment WHERE id=?',
                         (assessment_id,)).fetchone()
        if old:
            if old['log_id'] != log_id or old['param_hash'] != param_hash:
                raise ValueError('assessment_identity_conflict')
            return json.loads(old['body'])
        scans = _load_scans(db, log_id)
        engine = run_engine(scans, gap_seconds, clock_contract, cutoff_epoch, session_limit)
        body = {
            'assessment_id': assessment_id,
            'log_id': log_id,
            'source_hash': log['source_hash'],
            'algorithm_version': ALGORITHM_VERSION,
            'clock_contract': clock_contract,
            'gap_seconds': gap_seconds,
            'cutoff': instant(cutoff).astimezone(timezone.utc).isoformat(),
            'session_limit': session_limit,
            'param_hash': param_hash,
            'state': engine['state'],
            'input_summary': engine['input_summary'],
            'problems': engine['problems'],
            'paired_intervals': engine['paired_intervals'],
            'open_intervals': engine['open_intervals'],
            'result': engine['result']}
        with db:
            db.execute('INSERT INTO usage_assessment VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                       (assessment_id, log_id, log['batch_id'], log['source_hash'],
                        clock_contract, gap_seconds, body['cutoff'], session_limit,
                        param_hash, ALGORITHM_VERSION, engine['state'],
                        json.dumps(body, ensure_ascii=False, sort_keys=True)))
        return body
    finally:
        db.close()


def verify(db_path, assessment_id):
    """Re-pair from the frozen raw log rows and re-check witnesses, extrema
    and the stored conclusion.  Any tampering with scans, thresholds or offset
    witnesses yields an explicit problem code."""
    db = connect(db_path)
    db.executescript(SCHEMA)
    try:
        row = db.execute('SELECT * FROM usage_assessment WHERE id=?',
                         (assessment_id,)).fetchone()
        if not row:
            raise ValueError('unknown_assessment')
        problems = []
        log = db.execute('SELECT * FROM usage_log WHERE id=?', (row['log_id'],)).fetchone()
        if not log:
            problems.append('usage_log_missing')
            return problems
        if hashlib.sha256(log['source']).hexdigest() != log['source_hash']:
            problems.append('usage_log_source_hash_mismatch')
        stored = json.loads(row['body'])
        if stored.get('source_hash') != log['source_hash']:
            problems.append('assessment_source_hash_mismatch')
        if row['algorithm_version'] != ALGORITHM_VERSION \
                or stored.get('algorithm_version') != ALGORITHM_VERSION:
            problems.append('algorithm_version_drift')
        recomputed_hash = _param_digest(row['log_id'], log['source_hash'],
                                        row['gap_seconds'], row['clock_contract'],
                                        row['cutoff'], row['session_limit'])
        if row['param_hash'] != recomputed_hash or stored.get('param_hash') != recomputed_hash:
            problems.append('assessment_param_hash_mismatch')
        canonical = json.dumps(stored, ensure_ascii=False, sort_keys=True)
        if json.loads(canonical) != stored:
            problems.append('assessment_body_unstable')

        # Rebuild scans straight from the frozen raw bytes rather than the table.
        raw_scans = []
        for line in log['source'].decode('utf-8').splitlines():
            if not line.strip():
                continue
            raw_scans.append(json.loads(line))
        table_scans = _load_scans(db, row['log_id'])
        table_keys = {(s['event_id'], s['subject'], s['actor'], s['device'],
                       s['action'], s['reported_at'], s['error_seconds']) for s in table_scans}
        raw_keys = {(s['event_id'], s['subject'], s['actor'], s['device'], s['action'],
                     s['reported_at'], s['error_seconds']) for s in raw_scans}
        if table_keys != raw_keys:
            problems.append('usage_scan_table_drift')

        cutoff_epoch = _epoch(row['cutoff'])
        engine = run_engine(table_scans, row['gap_seconds'], row['clock_contract'],
                            cutoff_epoch, row['session_limit'])
        expected = {'state': engine['state'], 'input_summary': engine['input_summary'],
                    'problems': engine['problems'],
                    'paired_intervals': engine['paired_intervals'],
                    'open_intervals': engine['open_intervals'], 'result': engine['result']}
        for key, value in expected.items():
            if stored.get(key) != value:
                problems.append(f'assessment_conclusion_drift:{key}')

        # Independent witness replay: every stored offset witness must be
        # feasible for its device domain and reproduce the claimed count.
        if engine['result'] and engine['result']['contract'] == 'guaranteed' \
                and not engine['problems']:
            domains = engine['result']['device_offset_domains']
            intervals = _pair_scans(table_scans, cutoff_epoch)[2]
            for label, w in (('min_witness', engine['result']['min_witness']),
                             ('max_witness', engine['result']['max_witness'])):
                offsets = w['offset_witness']
                for device, off in offsets.items():
                    dom = domains.get(device)
                    if dom is None or not dom['min_offset'] <= off <= dom['max_offset']:
                        problems.append(f'witness_outside_domain:{label}:{device}')
                # Shared constant per device: cross-check against each scan row.
                for s in table_scans:
                    if s['reported_epoch'] <= cutoff_epoch and s['device'] in offsets:
                        if abs(offsets[s['device']]) > s['error_seconds']:
                            problems.append(f'witness_violates_scan_error:{label}:{s["event_id"]}')
                total, pair_sessions = _session_count_under_offsets(
                    intervals, row['gap_seconds'], offsets)
                claimed = engine['result'][label]['total_sessions']
                if total != claimed:
                    problems.append(f'witness_replay_count_mismatch:{label}')
        return problems
    finally:
        db.close()
