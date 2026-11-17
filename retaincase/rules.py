"""Retention adjudication, including time-of-as_of jurisdiction attribution.

Legacy batches (a single ``policy`` map keyed by subject category) keep the
original semantics.  A batch that declares ``jurisdictions`` / versioned
``policy_versions`` (or that contains jurisdiction attribution events) is
adjudicated per jurisdiction:

* attribution is replayed from source events up to ``as_of``; it is never
  inferred from the last imported row;
* a jurisdiction's retention start is selected by that jurisdiction's own
  policy version and its own evidence - a ``created`` start in J1 can never
  stand in for a missing ``created`` record in J2;
* legal holds replay independently and are never released by a transfer;
* the responsibility contract (``concurrent`` or ``single_successor``) is
  frozen on the run together with its authority basis.
"""
import json
import hashlib
from datetime import timedelta

from .store import connect
from .timeline import instant, utc_day

VALID_CONTRACTS = {'concurrent', 'single_successor'}
RETENTION_STARTS = {'created', 'terminated', 'last_use'}
ATTRIBUTION_KINDS = {'jurisdiction_origin', 'jurisdiction_transfer'}

def _config(db):
    return json.loads(db.execute('SELECT config_raw FROM batch LIMIT 1').fetchone()[0])


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _digest(value):
    return hashlib.sha256(_canonical(value).encode('utf-8')).hexdigest()


def _event_applies(event, subject, spec):
    """Own events plus tag-scoped hold and attribution events from other rows."""
    if event.get('subject') == subject:
        return True
    if event.get('kind') not in ({'hold_start', 'hold_end'} | ATTRIBUTION_KINDS):
        return False
    labels = set(spec.get('tags') or [])
    event_labels = set(event.get('tags') or [])
    if event.get('scope_tag'):
        event_labels.add(event['scope_tag'])
    return bool(labels & event_labels)


def _matched_events(subject, spec, all_events, as_of):
    matched = [event for event in all_events if _event_applies(event, subject, spec)]
    return sorted(matched, key=lambda e: (instant(e['at']) if e.get('at') else as_of,
                                          e['event_key']))


def _policy_models(config):
    """Flatten declared retention policy versions.

    Supported shapes::

        "jurisdictions": {"J1": {"start": "created", "days": 365}}
        "jurisdictions": {"J1": [{"id": "j1-2026", "start": ..., "days": ...,
                                  "effective_from": "...", "effective_until": "..."}]}
        "policy_versions": [{"id": ..., "jurisdiction": "J1", ...}]
    """
    models = []
    seen = set()

    def add(model, jurisdiction):
        start = model.get('start')
        if start not in RETENTION_STARTS:
            raise ValueError('unknown_policy_start')
        days = model.get('days')
        if not isinstance(days, int) or days < 0:
            raise ValueError('invalid_policy_days')
        key = (jurisdiction, model.get('id'), model.get('effective_from'))
        if key in seen:
            return
        seen.add(key)
        models.append({
            'id': str(model.get('id') or f'{jurisdiction}@{model.get("effective_from") or "open"}'),
            'jurisdiction': jurisdiction,
            'start': start,
            'days': days,
            'effective_from': model.get('effective_from'),
            'effective_until': model.get('effective_until'),
        })

    jurisdictions = config.get('jurisdictions') or {}
    for jurisdiction, value in jurisdictions.items():
        versions = value if isinstance(value, list) else [value]
        for version in versions:
            add(version, jurisdiction)
    for version in config.get('policy_versions') or []:
        jurisdiction = version.get('jurisdiction')
        if not jurisdiction:
            raise ValueError('policy_version_jurisdiction_required')
        add(version, jurisdiction)
    return models


def _policy_valid(model, as_of):
    if model['effective_from'] and instant(model['effective_from']) > as_of:
        return False
    if model['effective_until'] and instant(model['effective_until']) <= as_of:
        return False
    return True


def _select_policy(models, jurisdiction, as_of):
    candidates = [m for m in models
                  if m['jurisdiction'] == jurisdiction and _policy_valid(m, as_of)]
    if not candidates:
        return None, ['jurisdiction_policy_gap:' + jurisdiction]
    if len(candidates) > 1:
        return None, ['jurisdiction_policy_overlap:' + jurisdiction]
    return candidates[0], []


def _succession_record(event):
    """Return an explicit, verifiable liability-succession record, if any.

    A transfer only carries succession when it names both the releasing and
    assuming jurisdiction, a basis, and an evidence key that exists among the
    frozen source events.  Anything else leaves the concurrent obligations in
    place; it is not silently interpreted as an assumption.
    """
    payload = event
    record = payload.get('succession')
    source = payload.get('from_jurisdiction')
    target = payload.get('to_jurisdiction') or payload.get('jurisdiction')
    if isinstance(record, dict):
        basis = record.get('basis') or record.get('authority')
        evidence = record.get('evidence') or record.get('evidence_event_key')
        record_from = record.get('from_jurisdiction', source)
        record_to = record.get('to_jurisdiction', target)
        if basis and evidence and record_from == source and record_to == target:
            return {'basis': str(basis), 'evidence': str(evidence),
                    'from_jurisdiction': source, 'to_jurisdiction': target}
        return None
    if record is True:
        basis = payload.get('succession_basis')
        evidence = payload.get('succession_evidence')
        if basis and evidence:
            return {'basis': str(basis), 'evidence': str(evidence),
                    'from_jurisdiction': source, 'to_jurisdiction': target}
    return None


def _derive_attribution(events, as_of):
    """Replay origin/transfer events into half-open jurisdiction intervals."""
    items = [e for e in events
             if e.get('kind') in ATTRIBUTION_KINDS and e.get('at')
             and instant(e['at']) <= as_of]
    items.sort(key=lambda e: (instant(e['at']), e['event_key']))
    open_intervals = []          # [jurisdiction, start, end|None, closing transfer|None]
    origins = {}                 # jurisdiction -> earliest origin event
    history = []
    transfers = []
    conflicts = []
    event_keys = {e['event_key'] for e in events}

    def open_jurisdictions():
        return [item for item in open_intervals if item[2] is None]

    def add_conflict(code, detail, event, **extra):
        # One contradictory record should not multiply into per-subject noise.
        item = {'code': code, 'detail': detail, 'event_key': event['event_key'], **extra}
        if not any(x == item for x in conflicts):
            conflicts.append(item)

    for event in items:
        at = instant(event['at'])
        if event['kind'] == 'jurisdiction_origin':
            jurisdiction = event.get('jurisdiction')
            if not isinstance(jurisdiction, str) or not jurisdiction.strip():
                add_conflict('jurisdiction_conflict', 'origin_missing_jurisdiction', event)
                continue
            if jurisdiction in origins:
                origins[jurisdiction] = min(
                    (origins[jurisdiction], event),
                    key=lambda item: (instant(item['at']), item['event_key']))
            else:
                origins[jurisdiction] = event
            if any(x[0] == jurisdiction for x in open_jurisdictions()):
                # A second inception record while the holder is already open is
                # corroborating evidence, not a competing jurisdiction.
                continue
            if jurisdiction in history:
                # Re-inception without a recorded transfer back is contradictory.
                add_conflict('jurisdiction_conflict', 'origin_after_holder_closed',
                             event, jurisdiction=jurisdiction)
                continue
            competing = [x for x in open_jurisdictions() if x[0] != jurisdiction]
            if competing:
                add_conflict('jurisdiction_overlap', 'simultaneous_origin', event,
                             jurisdictions=sorted({x[0] for x in competing} | {jurisdiction}))
            open_intervals.append([jurisdiction, at, None, None])
            history.append(jurisdiction)
        else:
            source = event.get('from_jurisdiction')
            target = event.get('to_jurisdiction') or event.get('jurisdiction')
            if not source or not target or source == target:
                add_conflict('jurisdiction_conflict', 'invalid_transfer', event)
                continue
            source_open = [x for x in open_jurisdictions() if x[0] == source]
            if not source_open:
                add_conflict('jurisdiction_conflict', 'transfer_from_unattributed',
                             event, from_jurisdiction=source)
                continue
            if any(x[0] == target for x in open_jurisdictions()):
                add_conflict('jurisdiction_overlap', 'transfer_into_open_jurisdiction',
                             event, jurisdictions=[source, target])
                continue
            source_open[-1][2] = at
            transfer = {
                'event': event,
                'event_key': event['event_key'],
                'from_jurisdiction': source,
                'to_jurisdiction': target,
                'at': event['at'],
                'succession': None,
                'succession_unverified': False,
            }
            source_open[-1][3] = transfer
            succession = _succession_record(event)
            verifiable = bool(succession and succession['evidence'] in event_keys)
            transfer['succession'] = succession if verifiable else None
            transfer['succession_unverified'] = bool(succession and not verifiable)
            open_intervals.append([target, at, None, None])
            if target not in history:
                history.append(target)
            if succession and not verifiable:
                add_conflict('succession_unverified',
                             'succession_evidence_not_in_sources', event)
            transfers.append(transfer)

    current = []
    for jurisdiction, _start, end, _transfer in open_intervals:
        if end is None and jurisdiction not in current:
            current.append(jurisdiction)
    # A use/termination event labelled with a holder that did not hold the
    # object at that instant contradicts the replay and must be reviewed.
    for event in events:
        if event.get('kind') not in {'use', 'terminate'}:
            continue
        tagged = event.get('jurisdiction')
        if not tagged or not event.get('at'):
            continue
        at = instant(event['at'])
        covered = any(item[0] == tagged and item[1] <= at
                      and (item[2] is None or at < item[2]) for item in open_intervals)
        if not covered:
            add_conflict('jurisdiction_conflict', 'event_outside_holder', event,
                         jurisdiction=tagged)
    return {
        'items': items,
        'origins': origins,
        'history': history,
        'current': current,
        'intervals': open_intervals,
        'transfers': transfers,
        'conflicts': conflicts,
    }


def _release_transfers(attribution):
    """Yield (jurisdiction, closing transfer|None) for each closed interval."""
    return [(jurisdiction, transfer)
            for jurisdiction, _start, end, transfer in attribution['intervals']
            if end is not None]


def _single_successor_applicable(attribution):
    """Single-holder contract: drop a source only with recorded succession.

    Applicability is derived per held interval.  A holder whose release was
    accompanied by a verified succession record is excluded; a later transfer
    without one, or a re-acquisition, puts that holder back in force.  The
    currently open holder always constrains.
    """
    applicable = set()
    for jurisdiction, start, end, _transfer in attribution['intervals']:
        if end is None:
            applicable.add(jurisdiction)
    for jurisdiction, transfer in _release_transfers(attribution):
        if not transfer or not transfer['succession']:
            applicable.add(jurisdiction)
    return applicable


def _event_in_jurisdiction(event, jurisdiction, intervals):
    tagged = event.get('jurisdiction')
    if tagged:
        return tagged == jurisdiction
    if not event.get('at'):
        return False
    at = instant(event['at'])
    return any(item[0] == jurisdiction and item[1] <= at
               and (item[2] is None or at < item[2]) for item in intervals)


def _retention_start(jurisdiction, policy, events, as_of, attribution):
    """Choose this jurisdiction's own start; never borrow another's record."""
    kind = policy['start']
    if kind == 'created':
        origin = attribution['origins'].get(jurisdiction)
        if origin and instant(origin['at']) <= as_of:
            return origin['at'], origin, None
        return None, None, 'start_evidence_gap:' + jurisdiction
    wanted = 'terminate' if kind == 'terminated' else 'use'
    candidates = [e for e in events
                  if e.get('kind') == wanted and e.get('at')
                  and instant(e['at']) <= as_of
                  and _event_in_jurisdiction(e, jurisdiction, attribution['intervals'])]
    if not candidates:
        return None, None, f'start_evidence_gap:{jurisdiction}'
    chosen = max(candidates, key=lambda e: (instant(e['at']), e['event_key']))
    return chosen['at'], chosen, None


def _policy_record(policy):
    if not policy:
        return None
    body = {key: policy[key] for key in
            ('id', 'jurisdiction', 'start', 'days', 'effective_from', 'effective_until')}
    return {'body': body, 'digest': _digest(body)}


def _evaluate_jurisdiction_subject(subject, spec, events, as_of, config, models, contract):
    attribution = _derive_attribution(events, as_of)
    codes = []
    records = []

    if not attribution['items']:
        codes.append('jurisdiction_unknown')
    for conflict in attribution['conflicts']:
        # An unverifiable succession claim only matters to the contract that
        # would rely on it; under the concurrent contract it changes nothing.
        if conflict['code'] == 'succession_unverified' and contract == 'concurrent':
            continue
        codes.append(conflict['code'])

    history = attribution['history']
    applicable = (set(history) if contract == 'concurrent'
                  else _single_successor_applicable(attribution))

    succession_by_source = {}
    for jurisdiction, transfer in _release_transfers(attribution):
        if transfer and transfer['succession']:
            succession_by_source[jurisdiction] = transfer

    for jurisdiction in history:
        policy, policy_codes = _select_policy(models, jurisdiction, as_of)
        record = {
            'jurisdiction': jurisdiction,
            'applicability': 'applied' if jurisdiction in applicable else 'excluded',
            'basis': ('concurrent_all_sources' if contract == 'concurrent'
                      else ('single_holder' if jurisdiction in applicable
                            else 'succession_assumed')),
            'policy': _policy_record(policy),
            'start': None,
            'expires_on': None,
            'expired': None,
            'evidence_gap': None,
            'succession': None,
            'exclusion_basis': None,
        }
        if jurisdiction in applicable:
            codes.extend(policy_codes)
            if policy_codes:
                record['evidence_gap'] = policy_codes[0]
            if policy:
                start_at, start_event, gap = _retention_start(
                    jurisdiction, policy, events, as_of, attribution)
                if gap:
                    codes.append(gap)
                    record['evidence_gap'] = gap
                else:
                    expiry = utc_day(start_at) + timedelta(days=policy['days'])
                    expired = expiry <= as_of.date()
                    record['start'] = {
                        'kind': policy['start'],
                        'at': start_at,
                        'event_key': start_event['event_key'],
                        'event_id': start_event.get('_id'),
                    }
                    record['expires_on'] = expiry.isoformat()
                    record['expired'] = expired
                    if not expired:
                        codes.append('not_expired:' + jurisdiction)
                    record['start_event'] = start_event
        else:
            transfer = succession_by_source.get(jurisdiction)
            if transfer:
                record['succession'] = {
                    'event_key': transfer['event_key'],
                    'event_id': transfer['event'].get('_id'),
                    'basis': transfer['succession']['basis'],
                    'evidence': transfer['succession']['evidence'],
                    'from_jurisdiction': transfer['from_jurisdiction'],
                    'to_jurisdiction': transfer['to_jurisdiction'],
                }
                record['exclusion_basis'] = 'succession_assumed'
            # An excluded holder still reports the policy version and the start
            # it would have used, so the exclusion can be reviewed without
            # trusting a summary.  Its clock does not affect the decision.
            if policy:
                start_at, start_event, gap = _retention_start(
                    jurisdiction, policy, events, as_of, attribution)
                if gap:
                    record['evidence_gap'] = gap
                else:
                    expiry = utc_day(start_at) + timedelta(days=policy['days'])
                    record['start'] = {
                        'kind': policy['start'],
                        'at': start_at,
                        'event_key': start_event['event_key'],
                        'event_id': start_event.get('_id'),
                    }
                    record['expires_on'] = expiry.isoformat()
                    record['expired'] = expiry <= as_of.date()
            elif policy_codes:
                record['evidence_gap'] = policy_codes[0]
        records.append(record)

    # Holds replay from their own events and are unaffected by transfers.
    holds = {}
    active_holds = []
    dependencies = set()
    for event in events:
        if not event.get('at') or instant(event['at']) > as_of:
            continue
        if event['kind'] == 'hold_start':
            holds[event['hold_id']] = event['at']
        elif event['kind'] == 'hold_end':
            if event['hold_id'] not in holds:
                codes.append('unmatched_hold_release')
            else:
                holds.pop(event['hold_id'])
        elif event['kind'] == 'depends_on':
            dependencies.add(event['parent'])
    active_holds = list(holds)
    if active_holds:
        codes.append('legal_hold')

    hard = set()
    for code in codes:
        if code in {'evidence_gap', 'unmatched_hold_release', 'jurisdiction_unknown',
                    'jurisdiction_overlap', 'jurisdiction_conflict',
                    'succession_unverified', 'dependency_cycle'}:
            hard.add(code)
        elif code.startswith(('jurisdiction_policy_gap', 'jurisdiction_policy_overlap',
                              'start_evidence_gap')):
            hard.add(code)
    status = '证据不足' if hard else ('冻结' if codes else '可销毁')
    detail = {
        'contract': contract,
        'attribution': {
            'history': history,
            'current': attribution['current'],
            'conflicts': attribution['conflicts'],
        },
        'jurisdictions': [
            {k: v for k, v in record.items() if k != 'start_event'}
            for record in records
        ],
    }
    return status, codes, detail, records, dependencies


def _legacy_decision(subject, spec, events, config, as_of):
    """Original single-category policy path, kept byte-for-byte in effect."""
    codes = []
    start_kind = config['policy'][spec['category']]['start']
    if start_kind == 'created':
        start = spec.get('created')
    elif start_kind == 'terminated':
        ends = [e['at'] for e in events
                if e['kind'] == 'terminate' and e.get('at') and instant(e['at']) <= as_of]
        start = max(ends, key=instant) if ends else None
    elif start_kind == 'last_use':
        uses = [e['at'] for e in events
                if e['kind'] == 'use' and e.get('at') and instant(e['at']) <= as_of]
        start = max(uses, key=instant) if uses else None
    else:
        raise ValueError('unknown_policy_start')
    if not start:
        codes.append('evidence_gap')
    holds = {}
    dependencies = set()
    for event in events:
        if not event.get('at'):
            continue
        if event['kind'] == 'hold_start' and instant(event['at']) <= as_of:
            holds[event['hold_id']] = event['at']
        if event['kind'] == 'hold_end' and instant(event['at']) <= as_of:
            if event['hold_id'] not in holds:
                codes.append('unmatched_hold_release')
            else:
                holds.pop(event['hold_id'])
        if event['kind'] == 'depends_on' and instant(event['at']) <= as_of:
            dependencies.add(event['parent'])
    if start and utc_day(start) + timedelta(days=config['policy'][spec['category']]['days']) > as_of.date():
        codes.append('not_expired')
    if holds:
        codes.append('legal_hold')
    status = ('证据不足' if {'evidence_gap', 'unmatched_hold_release'} & set(codes)
              else ('冻结' if codes else '可销毁'))
    return status, codes, dependencies


def evaluate(path, contract=None, authority=None):
    db = connect(path)
    config = _config(db)
    rows = [dict(r) for r in db.execute('SELECT * FROM raw_event ORDER BY at,id')]
    all_events = []
    grouped = {subject: [] for subject in config['subjects']}
    event_by_key = {}
    for row in rows:
        payload = json.loads(row['payload'])
        payload['_id'] = row['id']
        payload['_source'] = row['source_id']
        all_events.append(payload)
        event_by_key[payload['event_key']] = row
        grouped.setdefault(payload['subject'], []).append(payload)
    as_of = instant(config['as_of'])
    models = _policy_models(config)
    jurisdiction_mode = bool(config.get('jurisdictions') or config.get('policy_versions')
                             or any(e.get('kind') in ATTRIBUTION_KINDS for e in all_events))
    contract = contract or config.get('jurisdiction_contract', 'concurrent')
    authority = authority or config.get('jurisdiction_authority')
    if jurisdiction_mode:
        if contract not in VALID_CONTRACTS:
            raise ValueError('unknown_jurisdiction_contract')
        if not authority:
            raise ValueError('jurisdiction_authority_required')

    decision = {}
    issues = {}
    dependencies = {}
    used_events = {}
    subject_details = {}
    subject_records = {}
    source_conflicts = {}
    if jurisdiction_mode:
        # An unresolved source conflict can change which attribution events are
        # real.  It is adjudicated in the decision, not left as a loose issue.
        for row in db.execute(
                "SELECT subject,code,detail FROM issue WHERE run_id IS NULL "
                "AND subject IS NOT NULL AND code='identity_conflict' ORDER BY id"):
            source_conflicts.setdefault(row['subject'], []).append(row['code'])

    for subject, spec in config['subjects'].items():
        events = _matched_events(subject, spec, all_events, as_of)
        used_events[subject] = [event_by_key[e['event_key']] for e in events]
        if jurisdiction_mode:
            status, codes, detail, records, deps = _evaluate_jurisdiction_subject(
                subject, spec, events, as_of, config, models, contract)
            for code in source_conflicts.get(subject, []):
                detail['source_conflict'] = True
                if code not in codes:
                    codes.append(code)
            if source_conflicts.get(subject):
                status = '证据不足'
            dependencies[subject] = set(deps)
            subject_details[subject] = detail
            subject_records[subject] = records
        else:
            status, codes, deps = _legacy_decision(
                subject, spec, events, config, as_of)
            dependencies[subject] = set(deps)
            subject_details[subject] = None
            subject_records[subject] = []
        decision[subject] = status
        issues[subject] = codes

    # Dependency closure: a retained descendant freezes every ancestor.
    visiting = set()
    visited = set()
    cycles = set()

    def visit(node):
        if node in visiting:
            cycles.update(visiting)
            return
        if node in visited:
            return
        visiting.add(node)
        for parent in dependencies.get(node, set()):
            visit(parent)
        visiting.remove(node)
        visited.add(node)

    for node in dependencies:
        visit(node)
    for node in cycles:
        if node in decision:
            decision[node] = '证据不足'
            issues[node].append('dependency_cycle')
    changed = True
    for _ in range(len(decision) + 1):
        if not changed:
            break
        changed = False
        for child, parents in dependencies.items():
            for parent in parents:
                if parent not in decision:
                    issues[child].append('missing_dependency')
                    decision[child] = '证据不足'
                    continue
                if decision[child] != '可销毁' and decision[parent] == '可销毁':
                    decision[parent] = '冻结'
                    issues[parent].append('dependent_retained')
                    changed = True
    else:
        for child in dependencies:
            decision[child] = '证据不足'
            issues[child].append('dependency_cycle')
    for _ in range(len(decision)):
        changed = False
        for child, parents in dependencies.items():
            for parent in parents:
                if parent not in used_events:
                    continue
                known = {e['id'] for e in used_events[parent]}
                added = [e for e in used_events[child] if e['id'] not in known]
                if added:
                    used_events[parent].extend(added)
                    changed = True
        if not changed:
            break

    snapshot = None
    if jurisdiction_mode:
        snapshot = {
            'contract': contract,
            'authority': authority,
            'as_of': config['as_of'],
            'policies': sorted(
                ({'id': m['id'], 'jurisdiction': m['jurisdiction'], 'start': m['start'],
                  'days': m['days'], 'effective_from': m['effective_from'],
                  'effective_until': m['effective_until'], 'digest': _digest(m)}
                 for m in models),
                key=lambda item: (item['jurisdiction'], item['id'])),
        }

    with db:
        run = db.execute("INSERT INTO run(batch_id,status) VALUES (?, '待接收')",
                         (config['batch_id'],)).lastrowid
        db.execute("UPDATE run SET status='已校验' WHERE id=?", (run,))
        if jurisdiction_mode:
            frozen = _canonical(snapshot)
            db.execute('INSERT INTO run_jurisdiction VALUES (?,?,?,?,?,?)',
                       (run, contract, authority, config['as_of'], frozen, _digest(snapshot)))
            for model in models:
                body = _canonical(model)
                db.execute('INSERT OR IGNORE INTO rule_version VALUES (?,?,?)',
                           ('policy:' + model['id'], body, _digest(model)))
        for subject, status in decision.items():
            for code in sorted(set(issues[subject])):
                db.execute('INSERT INTO issue(run_id,subject,code,detail) VALUES (?,?,?,?)',
                           (run, subject, code, code))
            detail = {
                'events': grouped.get(subject, []),
                'event_ids': sorted(e['id'] for e in used_events[subject]),
                'rules': config['rule_version'],
                'issues': issues[subject],
            }
            if subject_details[subject] is not None:
                detail['jurisdiction'] = subject_details[subject]
            db.execute('INSERT INTO evidence(run_id,subject,rule_id,detail) VALUES (?,?,?,?)',
                       (run, subject, config['rule_version'], json.dumps(detail, ensure_ascii=False)))
            for event in used_events[subject]:
                db.execute('INSERT INTO evidence(run_id,subject,source_id,event_id,rule_id,detail) VALUES (?,?,?,?,?,?)',
                           (run, subject, event['source_id'], event['id'],
                            config['rule_version'], 'decision_input'))
            for record in subject_records[subject]:
                policy = record['policy'] or {}
                start = record['start'] or {}
                succession = record['succession'] or {}
                db.execute(
                    'INSERT INTO jurisdiction_evidence VALUES '
                    '(NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (run, subject, record['jurisdiction'],
                     'applied' if record['applicability'] == 'applied' else 'excluded',
                     record['basis'],
                     policy.get('body', {}).get('id'),
                     _canonical(policy['body']) if policy else None,
                     policy.get('digest'),
                     policy.get('body', {}).get('effective_from'),
                     policy.get('body', {}).get('effective_until'),
                     policy.get('body', {}).get('start'),
                     start.get('at'),
                     start.get('event_id'),
                     start.get('event_key'),
                     record.get('expires_on'),
                     None if record.get('expired') is None else int(record['expired']),
                     record.get('evidence_gap'),
                     succession.get('event_id'),
                     succession.get('event_key'),
                     succession.get('basis') or succession.get('evidence'),
                     record.get('exclusion_basis')))
            db.execute('INSERT INTO decision(run_id,subject,status,detail) VALUES (?,?,?,?)',
                       (run, subject, status, json.dumps(detail, ensure_ascii=False)))
        db.execute("UPDATE run SET status=CASE WHEN EXISTS(SELECT 1 FROM decision WHERE run_id=? AND status='证据不足') THEN '待核' ELSE '已判定' END,ended_at=CURRENT_TIMESTAMP WHERE id=?",
                   (run, run))
    db.close()
    return decision


def action(command, path, sandbox=None, out=None, contract=None, authority=None):
    db = connect(path)
    config = _config(db)
    if command == 'recheck':
        if out:
            from pathlib import Path
            raw = Path(out).read_bytes()
            new = json.loads(raw)
            if new['batch_id'] != config['batch_id'] or new['rule_version'] == config['rule_version']:
                raise ValueError('invalid_rule_revision')
            with db:
                digest = hashlib.sha256(raw).hexdigest()
                db.execute('INSERT INTO rule_version VALUES (?,?,?)',
                           (new['rule_version'], json.dumps(new, sort_keys=True), digest))
                db.execute('UPDATE batch SET config_raw=?,config_hash=? WHERE id=?',
                           (raw, digest, config['batch_id']))
        db.close()
        return evaluate(path, contract=contract, authority=authority)
    if command == 'plan':
        rows = db.execute('SELECT subject,status FROM decision WHERE run_id=(SELECT max(id) FROM run) ORDER BY subject').fetchall()
        plan = [{'subject': r['subject'], 'path': config['subjects'][r['subject']]['path'],
                 'sha256': config['subjects'][r['subject']].get('sha256', '')}
                for r in rows if r['status'] == '可销毁']
        deps = {}
        for event in db.execute("SELECT subject,payload FROM raw_event WHERE kind='depends_on'"):
            item = json.loads(event['payload'])
            deps.setdefault(item['parent'], set()).add(item['subject'])
        by_id = {item['subject']: item for item in plan}
        ordered = []
        visiting = set()
        seen = set()

        def visit(subject):
            if subject in visiting:
                raise ValueError('dependency_cycle')
            if subject in seen:
                return
            visiting.add(subject)
            for child in sorted(deps.get(subject, ())):
                if child in by_id:
                    visit(child)
            visiting.remove(subject)
            seen.add(subject)
            ordered.append(by_id[subject])

        for subject in sorted(by_id):
            visit(subject)
        plan = ordered
        targets = [x['path'] for x in plan]
        from pathlib import Path
        if len(set(targets)) != len(targets) or any(Path(x).is_absolute() or '..' in Path(x).parts for x in targets):
            raise ValueError('unsafe_plan')
        destination = Path(out or 'plan.json')
        body = json.dumps(plan, ensure_ascii=False, indent=2)
        digest = hashlib.sha256(body.encode('utf-8')).hexdigest()
        with db:
            db.execute('INSERT OR IGNORE INTO plan(run_id,digest,body) VALUES ((SELECT max(id) FROM run),?,?)',
                       (digest, body))
        destination.write_text(body, encoding='utf-8')
        db.close()
        return str(destination)
    if command == 'execute':
        from pathlib import Path
        if not sandbox:
            raise ValueError('sandbox_required')
        root = Path(sandbox).resolve()
        root.mkdir(parents=True, exist_ok=True)
        frozen = db.execute('SELECT config_raw,config_hash FROM batch WHERE id=?', (config['batch_id'],)).fetchone()
        if hashlib.sha256(frozen['config_raw']).hexdigest() != frozen['config_hash']:
            raise ValueError('batch_config_tampered')
        body = Path(out or 'plan.json').read_text(encoding='utf-8')
        digest = hashlib.sha256(body.encode('utf-8')).hexdigest()
        latest = db.execute('SELECT max(id) FROM run').fetchone()[0]
        if not db.execute('SELECT 1 FROM plan WHERE digest=? AND run_id=? AND body=?',
                          (digest, latest, body)).fetchone():
            raise ValueError('plan_not_authorized_for_latest_run')
        plan = json.loads(body)
        done = []
        eligible = {r['subject'] for r in db.execute(
            "SELECT subject FROM decision WHERE run_id=? AND status='可销毁'", (latest,))}
        if {item['subject'] for item in plan} != eligible or len(plan) != len(eligible):
            raise ValueError('plan_decision_mismatch')
        for item in plan:
            spec = config['subjects'].get(item['subject'])
            if not spec or item['path'] != spec['path'] or item['sha256'] != spec.get('sha256', ''):
                raise ValueError('plan_config_mismatch')
        for item in plan:
            target = (root / item['path']).resolve()
            if root not in target.parents:
                raise ValueError('unsafe_path')
            if not target.exists():
                if db.execute('SELECT 1 FROM execution WHERE subject=? AND action=? AND before_hash=?',
                              (item['subject'], 'destroy', item['sha256'])).fetchone():
                    continue
                raise ValueError('target_missing')
            raw = target.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            if not item['sha256'] or digest != item['sha256']:
                raise ValueError('hash_changed')
            target.unlink()
            with db:
                db.execute('INSERT OR IGNORE INTO execution(run_id,subject,action,before_hash,after_state) VALUES ((SELECT max(id) FROM run),?,?,?,?)',
                           (item['subject'], 'destroy', digest, 'absent'))
            done.append(item['subject'])
        db.close()
        return done
    raise ValueError('unsupported_action')


def verify_decisions(path):
    import tempfile
    import sqlite3
    from pathlib import Path
    db = connect(path)
    latest = db.execute('SELECT max(id) FROM run').fetchone()[0]
    old = {r['subject']: r['status'] for r in db.execute(
        'SELECT subject,status FROM decision WHERE run_id=?', (latest,))}
    frozen = db.execute('SELECT contract,authority FROM run_jurisdiction WHERE run_id=?',
                        (latest,)).fetchone()
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / 'check.db'
        other = sqlite3.connect(copy)
        db.backup(other)
        other.close()
        if frozen:
            computed = evaluate(copy, contract=frozen['contract'], authority=frozen['authority'])
        else:
            computed = evaluate(copy)
    db.close()
    return [f'decision_mismatch:{k}' for k in old.keys() | computed.keys()
            if old.get(k) != computed.get(k)]
