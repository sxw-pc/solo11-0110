"""Minimized analytic delivery: single-package k-anonymity and cross-package intersection control.

A *delivery request* is frozen in the ledger before any file is written. Packages for the same
recipient are cross-checked by internal subject identity (never by per-request pseudonyms): a
published class whose non-empty intersection with an observable prior class falls below k cannot
be released at the proposed granularity. Two routes are legal:

* hold_new    - suspend the whole new package when the base proposal is unsafe.
* coarsen_new - search the declared generalization lattice for the minimum-loss safe proposal.

All on-disk writes are atomic staging-directory renames; an interrupted run never leaves a
readable half package or overwrites a previously legal package.
"""
import hashlib
import json
import os
import re
import secrets
from pathlib import Path

from .store import connect

SCHEMA = """
CREATE TABLE IF NOT EXISTS delivery_request(
  request_id TEXT PRIMARY KEY,
  inventory_id TEXT NOT NULL,
  run_id INTEGER NOT NULL,
  recipient TEXT NOT NULL,
  purpose TEXT NOT NULL,
  k_value INTEGER NOT NULL CHECK(k_value >= 1),
  route TEXT NOT NULL CHECK(route IN ('hold_new','coarsen_new')),
  max_suppression INTEGER NOT NULL CHECK(max_suppression >= 0),
  spec_raw TEXT NOT NULL,
  spec_hash TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  decision_hash TEXT NOT NULL,
  package_salt_hash TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('frozen','held','published','revoked')),
  hold_reason TEXT,
  package_path TEXT,
  package_hash TEXT,
  proof_hash TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS delivery_field(
  request_id TEXT NOT NULL REFERENCES delivery_request(request_id),
  field TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('quasi','analytic')),
  base_level INTEGER NOT NULL,
  PRIMARY KEY(request_id,field));
CREATE TABLE IF NOT EXISTS delivery_lineage(
  request_id TEXT NOT NULL REFERENCES delivery_request(request_id),
  field TEXT NOT NULL,
  input_field TEXT NOT NULL,
  reversible INTEGER NOT NULL,
  PRIMARY KEY(request_id,field,input_field));
CREATE TABLE IF NOT EXISTS delivery_level(
  request_id TEXT NOT NULL REFERENCES delivery_request(request_id),
  field TEXT NOT NULL,
  level INTEGER NOT NULL,
  cost INTEGER NOT NULL,
  PRIMARY KEY(request_id,field,level));
CREATE TABLE IF NOT EXISTS delivery_pseudo(
  request_id TEXT NOT NULL REFERENCES delivery_request(request_id),
  subject TEXT NOT NULL,
  pseudonym TEXT NOT NULL,
  PRIMARY KEY(request_id,subject));
CREATE TABLE IF NOT EXISTS delivery_class(
  request_id TEXT NOT NULL REFERENCES delivery_request(request_id),
  class_no INTEGER NOT NULL,
  subject TEXT NOT NULL,
  generalized_key TEXT NOT NULL,
  suppressed INTEGER NOT NULL,
  PRIMARY KEY(request_id,class_no,subject));
CREATE TABLE IF NOT EXISTS delivery_intersection(
  request_id TEXT NOT NULL REFERENCES delivery_request(request_id),
  class_no INTEGER NOT NULL,
  prior_request_id TEXT NOT NULL,
  prior_class_no INTEGER NOT NULL,
  overlap_count INTEGER NOT NULL,
  meets_k INTEGER NOT NULL,
  protected INTEGER NOT NULL,
  PRIMARY KEY(request_id,class_no,prior_request_id,prior_class_no,protected));
"""

VALID_ROUTES = ('hold_new', 'coarsen_new')


def _digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False).encode('utf-8')).hexdigest()


# --------------------------------------------------------------------------- #
# Inventory and spec validation
# --------------------------------------------------------------------------- #

def _load_inventory(db, inventory_id):
    receipt = db.execute('SELECT * FROM minimization_inventory WHERE inventory_id=?',
                         (inventory_id,)).fetchone()
    if not receipt:
        raise ValueError('unknown_inventory')
    rows = [dict(r) for r in db.execute(
        'SELECT subject,field,value,classification FROM minimization_field '
        'WHERE inventory_id=? ORDER BY subject,field', (inventory_id,))]
    by_field = {}
    for row in rows:
        by_field.setdefault(row['field'], {})[row['subject']] = row
    return dict(receipt), rows, by_field


def _field_classes(inventory_rows):
    out = {}
    for row in inventory_rows:
        out.setdefault(row['field'], set()).add(row['classification'])
    return out


def _validate_spec(spec, inventory_rows, field_index):
    if not isinstance(spec, dict):
        raise ValueError('spec_must_be_object')
    deliverable = spec.get('deliverable_fields')
    lattice = spec.get('lattice')
    if not isinstance(deliverable, list) or not deliverable:
        raise ValueError('deliverable_fields_required')
    if not isinstance(lattice, dict):
        raise ValueError('lattice_required')
    if any(not isinstance(f, str) or not f for f in deliverable):
        raise ValueError('field_name_invalid')
    if len(set(deliverable)) != len(deliverable):
        raise ValueError('deliverable_field_duplicate')

    field_class = _field_classes(inventory_rows)
    for field in deliverable:
        if field not in field_index:
            raise ValueError(f'deliverable_field_not_in_inventory:{field}')
        if 'direct' in field_class[field]:
            raise ValueError(f'direct_field_forbidden:{field}')

    lineage_decl = spec.get('lineage', {})
    if not isinstance(lineage_decl, dict):
        raise ValueError('lineage_must_be_object')

    lineage = {}
    unverified = set()
    # Every derived deliverable field must declare sources; declarations for intermediate
    # derived fields (themselves not delivered) are parsed too so transitive chains resolve.
    for field in deliverable:
        if 'derived' not in field_class[field]:
            continue
        decl = lineage_decl.get(field)
        if not isinstance(decl, dict) or not isinstance(decl.get('inputs'), list) \
                or not decl['inputs']:
            unverified.add(field)
    for field, decl in lineage_decl.items():
        if not isinstance(field, str) or not field:
            raise ValueError('lineage_field_invalid')
        if not isinstance(decl, dict) or not isinstance(decl.get('inputs'), list) \
                or not decl['inputs']:
            raise ValueError(f'lineage_declaration_invalid:{field}')
        reversible = bool(decl.get('reversible', False))
        inputs = []
        for input_field in decl['inputs']:
            if not isinstance(input_field, str) or not input_field:
                raise ValueError('lineage_input_invalid')
            if input_field not in field_index:
                if field in deliverable:
                    unverified.add(field)
                continue
            inputs.append((input_field, reversible))
        lineage[field] = inputs

    # Transitive check: a reversible derived field is excluded whenever any reversible ancestor
    # chain reaches a direct field. A missing source relation stays unverified, never rejected.
    def reaches_direct(field, seen):
        if field in seen:
            return False
        seen = seen | {field}
        for input_field, reversible in lineage.get(field, ()):
            if not reversible:
                continue
            if 'direct' in field_class.get(input_field, set()):
                return True
            if reaches_direct(input_field, seen):
                return True
        return False

    rejected = sorted({f for f in deliverable
                       if 'derived' in field_class[f] and reaches_direct(f, set())})
    if rejected:
        raise ValueError('derived_reversible_direct:' + ','.join(rejected))

    quasi = spec.get('quasi_identifiers')
    if not isinstance(quasi, list) or not quasi:
        raise ValueError('quasi_identifiers_required')
    if len(set(quasi)) != len(quasi) or any(f not in deliverable for f in quasi):
        raise ValueError('quasi_not_in_deliverable')
    analytic = [f for f in deliverable if f not in quasi]

    parsed_lattice = {}
    base_levels = {}
    for field in quasi:
        levels = lattice.get(field)
        if not isinstance(levels, list) or not levels:
            raise ValueError(f'lattice_levels_required:{field}')
        costs = []
        for idx, level in enumerate(levels):
            if not isinstance(level, dict) or not isinstance(level.get('name'), str) \
                    or not isinstance(level.get('cost'), int) or level['cost'] < 0 \
                    or ('buckets' not in level and 'prefix' not in level and idx > 0):
                raise ValueError(f'lattice_level_invalid:{field}')
            if idx > 0 and 'buckets' not in level and not (
                    isinstance(level.get('prefix'), int) and level['prefix'] >= 0):
                raise ValueError(f'lattice_level_invalid:{field}')
            costs.append(level['cost'])
        if costs[0] != 0:
            raise ValueError(f'lattice_base_must_be_identity:{field}')
        if any(costs[i] > costs[i + 1] for i in range(len(costs) - 1)):
            raise ValueError(f'lattice_cost_not_monotone:{field}')
        parsed_lattice[field] = levels
        base = spec.get('base_levels', {}).get(field, 0)
        if not isinstance(base, int) or not 0 <= base < len(levels):
            raise ValueError(f'base_level_invalid:{field}')
        base_levels[field] = base

    k = spec.get('k')
    if not isinstance(k, int) or k < 1:
        raise ValueError('k_must_be_positive_int')
    max_suppression = spec.get('max_suppression', 0)
    if not isinstance(max_suppression, int) or max_suppression < 0:
        raise ValueError('max_suppression_invalid')

    return {
        'subjects': sorted({row['subject'] for row in inventory_rows}),
        'quasi': quasi,
        'analytic': analytic,
        'lineage': lineage,
        'unverified': sorted(unverified),
        'lattice': parsed_lattice,
        'base_levels': base_levels,
        'k': k,
        'max_suppression': max_suppression,
    }


# --------------------------------------------------------------------------- #
# Generalization, equivalence classes, cross-package intersections
# --------------------------------------------------------------------------- #

def _generalize(field, value, level_idx, lattice):
    """Level 0 is identity; higher levels use explicit buckets or fixed prefixes."""
    if level_idx == 0:
        return value
    level = lattice[field][level_idx]
    if 'buckets' in level:
        buckets = level['buckets']
        if value not in buckets:
            raise ValueError(f'generalization_bucket_missing:{field}:{value}')
        return str(buckets[value])
    return value[:level['prefix']]


def _partition(eligible, field_index, quasi, levels, lattice):
    classes = {}
    for subject in eligible:
        key = tuple(
            _generalize(f, field_index[f][subject]['value'], levels[f], lattice) for f in quasi)
        classes.setdefault(key, []).append(subject)
    return [(key, sorted(classes[key])) for key in sorted(classes)]


def _prior_classes(db, recipient, exclude_request=None):
    """Packages accessible to this recipient, represented by internal identity classes.

    Revoked packages stay in the set: revocation withdraws the deliverable conclusion, but the
    recipient may physically still hold the bytes, so ignoring them would weaken cross-package
    protection. Held requests never produced files and recorded no classes. The request being
    verified is excluded: intersecting a package with itself would mask real sub-k overlaps.
    """
    result = []
    for row in db.execute(
            "SELECT request_id FROM delivery_request WHERE recipient=? "
            "AND state IN ('published','revoked') ORDER BY created_at, request_id",
            (recipient,)):
        if row['request_id'] == exclude_request:
            continue
        classes = {}
        for member in db.execute(
                'SELECT class_no,subject FROM delivery_class WHERE request_id=? AND suppressed=0 '
                'ORDER BY class_no,subject', (row['request_id'],)):
            classes.setdefault(member['class_no'], []).append(member['subject'])
        result.append((row['request_id'], [sorted(v) for _, v in sorted(classes.items())]))
    return result


def _cross_violations(partition, prior, k):
    """Non-empty intersections below k violate. Absent/suppressed subjects belong to no class."""
    violating = set()
    evidence = {}
    for idx, (_, members) in enumerate(partition):
        member_set = set(members)
        entries = []
        for prior_id, prior_partition in prior:
            for prior_no, prior_members in enumerate(prior_partition):
                overlap = member_set & set(prior_members)
                if not overlap:
                    continue
                meets = len(overlap) >= k
                entries.append({'prior_request_id': prior_id, 'prior_class_no': prior_no,
                                'overlap_count': len(overlap), 'meets_k': meets})
                if not meets:
                    violating.add(idx)
        evidence[idx] = entries
    return violating, evidence


def _evaluate_levels(eligible, field_index, quasi, levels, lattice, k, max_suppression, prior):
    """Suppression is the union of local-small and cross-violating classes.

    The result is budget-feasible when the union fits max_suppression. Whether cross violations
    are allowed at all is a route decision made by the caller (hold_new never accepts them).
    """
    partition = _partition(eligible, field_index, quasi, levels, lattice)
    local_bad = {idx for idx, (_, members) in enumerate(partition) if len(members) < k}
    cross_bad, evidence = _cross_violations(partition, prior, k)
    bad = local_bad | cross_bad
    suppressed = sorted(s for idx in bad for s in partition[idx][1])
    return {'partition': partition, 'suppressed': set(suppressed), 'class_bad': bad,
            'local_bad': local_bad, 'cross_bad': cross_bad, 'cross_evidence': evidence,
            'within_budget': len(suppressed) <= max_suppression,
            'suppression_count': len(suppressed)}


def _hold_new_verdict(info, field_index, prior):
    """hold_new publishes only at base granularity, with local suppression inside the budget."""
    evaluation = _evaluate_levels(info['subjects'], field_index, info['quasi'],
                                  dict(info['base_levels']), info['lattice'], info['k'],
                                  info['max_suppression'], prior)
    if evaluation['cross_bad']:
        return evaluation, 'intersection_below_k'
    if not evaluation['within_budget']:
        return evaluation, 'suppression_budget_exceeded'
    return evaluation, None


def _enumerate_level_vectors(quasi, lattice, base_levels):
    ordered_fields = sorted(quasi)
    ranges = [range(base_levels[f], len(lattice[f])) for f in ordered_fields]

    def walk(pos, current):
        if pos == len(ordered_fields):
            yield dict(current)
            return
        field = ordered_fields[pos]
        for level in ranges[pos]:
            current[field] = level
            yield from walk(pos + 1, current)

    yield from walk(0, {})


def _vector_cost(levels, lattice):
    return sum(lattice[f][lv]['cost'] for f, lv in levels.items())


def _base_cross_evidence(info, field_index, prior):
    """Intersection evidence at base levels independent of the suppression budget."""
    partition = _partition(info['subjects'], field_index, info['quasi'],
                           dict(info['base_levels']), info['lattice'])
    _, evidence = _cross_violations(partition, prior, info['k'])
    return evidence


def _choose_coarsening(info, field_index, prior):
    """Minimum (cost, level vector, suppression count, suppressed subjects in stable order).

    A cross-violating class is neutralized when it is isolated whole-row within the suppression
    budget: every remaining observable class then meets k both locally and against every prior
    package. hold_new's stricter rule (never suppress around a cross violation) lives in
    _hold_new_verdict.
    """
    ordered_fields = sorted(info['quasi'])
    best = None
    for levels in _enumerate_level_vectors(info['quasi'], info['lattice'], info['base_levels']):
        evaluation = _evaluate_levels(info['subjects'], field_index, info['quasi'], levels,
                                      info['lattice'], info['k'], info['max_suppression'], prior)
        if not evaluation['within_budget']:
            continue
        score = (_vector_cost(levels, info['lattice']),
                 tuple(levels[f] for f in ordered_fields),
                 len(evaluation['suppressed']),
                 tuple(sorted(evaluation['suppressed'])))
        if best is None or score < best[0]:
            best = (score, levels, evaluation)
    return None if best is None else (best[1], best[2])


# --------------------------------------------------------------------------- #
# Freeze / publish
# --------------------------------------------------------------------------- #

def freeze(db_path, request_id, inventory_id, recipient, purpose, route, spec, package_dir):
    if route not in VALID_ROUTES:
        raise ValueError('route_invalid')
    if not isinstance(recipient, str) or not recipient.strip():
        raise ValueError('recipient_required')
    if not isinstance(purpose, str) or not purpose.strip():
        raise ValueError('purpose_required')
    if not isinstance(request_id, str) or not request_id:
        raise ValueError('request_id_required')
    package_root = Path(package_dir).resolve()
    db = connect(db_path)
    closed = False
    try:
        db.executescript(SCHEMA)
        from .minimization import SCHEMA as MIN_SCHEMA
        db.executescript(MIN_SCHEMA)

        receipt, inventory_rows, field_index = _load_inventory(db, inventory_id)
        info = _validate_spec(spec, inventory_rows, field_index)

        source_path = spec.get('inventory_csv_path')
        if source_path is None:
            raise ValueError('inventory_csv_path_required')
        # Re-verify the original inventory bytes instead of trusting the frozen digest.
        if hashlib.sha256(Path(source_path).read_bytes()).hexdigest() != receipt['source_hash']:
            raise ValueError('inventory_source_changed')

        latest_run = db.execute('SELECT max(id) FROM run').fetchone()[0]
        if not latest_run:
            raise ValueError('evaluate_first')
        from .rules import reevaluate_to_temp
        reeval = reevaluate_to_temp(db_path)
        if reeval['run_id'] != latest_run or reeval['decisions'] != {
                r['subject']: r['status'] for r in db.execute(
                    'SELECT subject,status FROM decision WHERE run_id=?', (latest_run,))}:
            raise ValueError('decision_recompute_mismatch')
        decisions = reeval['decisions']
        decision_hash = _digest([[s, decisions[s]] for s in sorted(decisions)])

        from .requests import subject_release_gate
        gate = {}
        eligible = []
        for subject in info['subjects']:
            verdict = subject_release_gate(db, subject, latest_run)
            gate[subject] = verdict
            if verdict['eligible']:
                eligible.append(subject)
        info['subjects'] = sorted(eligible)
        if not info['subjects']:
            raise ValueError('no_eligible_subjects')

        spec_hash = _digest({'spec': spec, 'inventory_id': inventory_id, 'recipient': recipient,
                             'purpose': purpose, 'route': route})
        input_hash = _digest({'inventory_receipt': receipt, 'inventory_rows': inventory_rows,
                              'gate': {s: gate[s] for s in sorted(gate)}})

        existing = db.execute('SELECT * FROM delivery_request WHERE request_id=?',
                              (request_id,)).fetchone()
        if existing:
            if existing['spec_hash'] != spec_hash or existing['input_hash'] != input_hash:
                raise ValueError('request_identity_conflict')
            closed = True
            db.close()
            return _resume(db_path, request_id, package_root)

        if info['unverified']:
            state, hold_reason = 'held', 'lineage_unverified:' + ','.join(info['unverified'])
        else:
            prior = _prior_classes(db, recipient)
            if route == 'hold_new':
                _, reason = _hold_new_verdict(info, field_index, prior)
                if reason is None:
                    state, hold_reason = 'frozen', None
                else:
                    state, hold_reason = 'held', reason
            else:
                state, hold_reason = ('frozen', None) if _choose_coarsening(
                    info, field_index, prior) else ('held', 'no_feasible_coarsening')

        salt = secrets.token_hex(32)
        salt_hash = hashlib.sha256(salt.encode('utf-8')).hexdigest()
        spec_raw = json.dumps(spec, sort_keys=True, ensure_ascii=False)
        with db:
            db.execute(
                'INSERT INTO delivery_request(request_id,inventory_id,run_id,recipient,purpose,'
                'k_value,route,max_suppression,spec_raw,spec_hash,input_hash,decision_hash,'
                'package_salt_hash,state,hold_reason) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (request_id, inventory_id, latest_run, recipient, purpose, info['k'], route,
                 info['max_suppression'], spec_raw, spec_hash, input_hash, decision_hash,
                 salt_hash, state, hold_reason))
            db.executemany(
                'INSERT INTO delivery_field VALUES (?,?,?,?)',
                [(request_id, f, 'quasi' if f in info['quasi'] else 'analytic',
                  info['base_levels'].get(f, 0))
                 for f in info['quasi'] + info['analytic']])
            for field, inputs in info['lineage'].items():
                db.executemany('INSERT INTO delivery_lineage VALUES (?,?,?,?)',
                               [(request_id, field, input_field, 1 if reversible else 0)
                                for input_field, reversible in inputs])
            for field, levels in info['lattice'].items():
                db.executemany('INSERT INTO delivery_level VALUES (?,?,?,?)',
                               [(request_id, field, idx, level['cost'])
                                for idx, level in enumerate(levels)])
            for subject in info['subjects']:
                pseudonym = 'PS-' + hashlib.sha256(
                    (salt + '|' + request_id + '|' + subject).encode('utf-8')).hexdigest()[:16]
                db.execute('INSERT INTO delivery_pseudo VALUES (?,?,?)',
                           (request_id, subject, pseudonym))
        closed = True
        db.close()
        if state == 'held':
            return inspect(db_path, request_id)
        return _publish(db_path, request_id, package_root)
    finally:
        if not closed:
            db.close()


def _resume(db_path, request_id, package_root):
    db = connect(db_path)
    try:
        row = db.execute('SELECT * FROM delivery_request WHERE request_id=?',
                         (request_id,)).fetchone()
        if row['state'] in ('held', 'revoked'):
            return _describe_row(row)
    finally:
        db.close()
    # frozen (crashed before rename) or published: _publish re-checks run freshness first,
    # rebuilds deterministically from ledger data, and never overwrites a complete package.
    return _publish(db_path, request_id, package_root)


def _publish(db_path, request_id, package_root):
    package_root = Path(package_root).resolve()
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        row = db.execute('SELECT * FROM delivery_request WHERE request_id=?',
                         (request_id,)).fetchone()
        if not row:
            raise ValueError('unknown_delivery_request')
        if row['state'] == 'held':
            raise ValueError('request_held')
        if row['state'] == 'revoked':
            raise ValueError('request_revoked')
        target = package_root / request_id

        # Re-verify before (re)writing or confirming an existing package: a newer run
        # invalidates the frozen request even when the files are already on disk.
        latest_run = db.execute('SELECT max(id) FROM run').fetchone()[0]
        if latest_run != row['run_id']:
            with db:
                db.execute("UPDATE delivery_request SET state='held',hold_reason=? WHERE request_id=?",
                           ('decision_run_stale', request_id))
            return inspect(db_path, request_id)

        if row['state'] == 'published' and target.is_dir() \
                and (target / 'package.json').is_file():
            db.close()
            return inspect(db_path, request_id)

        receipt, inventory_rows, field_index = _load_inventory(db, row['inventory_id'])
        spec = json.loads(row['spec_raw'])
        info = _validate_spec(spec, inventory_rows, field_index)
        info['subjects'] = sorted(r['subject'] for r in db.execute(
            'SELECT subject FROM delivery_pseudo WHERE request_id=?', (request_id,)))
        prior = _prior_classes(db, row['recipient'])

        base_evidence = _base_cross_evidence(info, field_index, prior)
        if row['route'] == 'hold_new':
            base_eval, reason = _hold_new_verdict(info, field_index, prior)
            if reason is not None:
                with db:
                    db.execute("UPDATE delivery_request SET state='held',hold_reason=? WHERE request_id=?",
                               (reason, request_id))
                return inspect(db_path, request_id)
            levels, evaluation = dict(info['base_levels']), base_eval
        else:
            chosen = _choose_coarsening(info, field_index, prior)
            if chosen is None:
                with db:
                    db.execute("UPDATE delivery_request SET state='held',hold_reason=? WHERE request_id=?",
                               ('no_feasible_coarsening', request_id))
                return inspect(db_path, request_id)
            levels, evaluation = chosen

        package, proof = _render_package(db, row, info, field_index, levels, evaluation,
                                         base_evidence)
        staging = package_root / ('.staging-' + request_id)
        if staging.exists():
            _rm_tree(staging)
        staging.mkdir(parents=True)
        package_bytes = (json.dumps(package, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
        proof_bytes = (json.dumps(proof, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
        package_hash = hashlib.sha256(package_bytes).hexdigest()
        proof_hash = hashlib.sha256(proof_bytes).hexdigest()
        (staging / 'package.json').write_bytes(package_bytes)
        (staging / 'proof.json').write_bytes(proof_bytes)
        manifest = {'request_id': request_id, 'package_hash': package_hash,
                    'proof_hash': proof_hash, 'spec_hash': row['spec_hash'],
                    'input_hash': row['input_hash'], 'decision_hash': row['decision_hash'],
                    'run_id': row['run_id']}
        (staging / 'manifest.json').write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        _fsync_dir(staging)
        os.replace(staging, target)
        _fsync_dir(package_root)

        with db:
            if row['state'] != 'published':
                db.execute('UPDATE delivery_request SET state=?,package_path=?,package_hash=?,'
                           'proof_hash=? WHERE request_id=?',
                           ('published', str(target), package_hash, proof_hash, request_id))
            _record_classes(db, request_id, evaluation, base_evidence)
        return inspect(db_path, request_id)
    finally:
        db.close()


def _render_package(db, row, info, field_index, levels, evaluation, base_evidence):
    pseudo = {r['subject']: r['pseudonym'] for r in db.execute(
        'SELECT subject,pseudonym FROM delivery_pseudo WHERE request_id=?',
        (row['request_id'],))}
    suppressed = evaluation['suppressed']
    classes = []
    anonymous_no = 0
    for idx, (key, members) in enumerate(evaluation['partition']):
        is_suppressed = idx in evaluation['class_bad']
        if not is_suppressed:
            anonymous_no += 1
        classes.append({'class_no': idx,
                        'anonymous_no': anonymous_no if not is_suppressed else None,
                        'generalized_key': list(key), 'members': members,
                        'suppressed': is_suppressed})

    rows = []
    for subject in info['subjects']:
        if subject in suppressed:
            continue
        record = {'pseudonym': pseudo[subject]}
        for field in info['quasi']:
            record[field] = _generalize(field, field_index[field][subject]['value'],
                                        levels[field], info['lattice'])
        for field in info['analytic']:
            record[field] = field_index[field][subject]['value']
        rows.append(record)
    rows.sort(key=lambda r: r['pseudonym'])

    package = {
        'request_id': row['request_id'], 'recipient': row['recipient'],
        'purpose': row['purpose'], 'k': row['k_value'], 'route': row['route'],
        'levels': {f: {'level': levels[f], 'name': info['lattice'][f][levels[f]]['name']}
                   for f in sorted(info['quasi'])},
        'suppressed_count': len(suppressed), 'rows': rows,
    }

    intersections = []
    for idx, entries in evaluation['cross_evidence'].items():
        if idx in evaluation['class_bad']:
            continue
        anonymous_no = next(c['anonymous_no'] for c in classes if c['class_no'] == idx)
        for entry in entries:
            intersections.append({'class_no': idx, 'anonymous_no': anonymous_no,
                                  **entry, 'protected': False})
    # Base-level sub-k overlaps are the intersections that coarsening/suppression protected.
    protected = []
    for idx, entries in base_evidence.items():
        for entry in entries:
            if not entry['meets_k']:
                protected.append({'base_class_no': idx, **entry, 'protected': True})
    proof = {
        'request_id': row['request_id'], 'inventory_id': row['inventory_id'],
        'run_id': row['run_id'], 'spec_hash': row['spec_hash'],
        'input_hash': row['input_hash'], 'decision_hash': row['decision_hash'],
        'salt_hash': row['package_salt_hash'], 'levels': levels,
        'lineage': {f: [{'input': i, 'reversible': bool(rev)} for i, rev in inputs]
                    for f, inputs in info['lineage'].items()},
        'classes': classes, 'suppressed_subjects': sorted(suppressed),
        'intersections': intersections, 'protected_intersections': protected,
    }
    return package, proof


def _record_classes(db, request_id, evaluation, base_evidence):
    for idx, (key, members) in enumerate(evaluation['partition']):
        suppressed = 1 if idx in evaluation['class_bad'] else 0
        for subject in members:
            db.execute('INSERT OR IGNORE INTO delivery_class VALUES (?,?,?,?,?)',
                       (request_id, idx, subject,
                        json.dumps(list(key), ensure_ascii=False), suppressed))
    for idx, entries in evaluation['cross_evidence'].items():
        if idx in evaluation['class_bad']:
            continue
        for entry in entries:
            db.execute('INSERT OR IGNORE INTO delivery_intersection VALUES (?,?,?,?,?,?,?)',
                       (request_id, idx, entry['prior_request_id'], entry['prior_class_no'],
                        entry['overlap_count'], 1 if entry['meets_k'] else 0, 0))
    for idx, entries in base_evidence.items():
        for entry in entries:
            if not entry['meets_k']:
                db.execute('INSERT OR IGNORE INTO delivery_intersection VALUES (?,?,?,?,?,?,?)',
                           (request_id, idx, entry['prior_request_id'],
                            entry['prior_class_no'], entry['overlap_count'], 0, 1))


def _rm_tree(path):
    for child in path.iterdir():
        if child.is_file() or child.is_symlink():
            child.unlink()
        else:
            _rm_tree(child)
    path.rmdir()


def _fsync_dir(path):
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _describe_row(row):
    return {'request_id': row['request_id'], 'inventory_id': row['inventory_id'],
            'run_id': row['run_id'], 'recipient': row['recipient'], 'purpose': row['purpose'],
            'k': row['k_value'], 'route': row['route'], 'state': row['state'],
            'hold_reason': row['hold_reason'], 'package_path': row['package_path'],
            'package_hash': row['package_hash'], 'proof_hash': row['proof_hash']}


def inspect(db_path, request_id):
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        row = db.execute('SELECT * FROM delivery_request WHERE request_id=?',
                         (request_id,)).fetchone()
        if not row:
            raise ValueError('unknown_delivery_request')
        result = _describe_row(row)
        result['pseudonyms'] = {r['subject']: r['pseudonym'] for r in db.execute(
            'SELECT subject,pseudonym FROM delivery_pseudo WHERE request_id=? ORDER BY subject',
            (request_id,))}
        return result
    finally:
        db.close()


def report(db_path, request_id):
    """Public-safe report: overlap counts and anonymous group numbers only."""
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        row = db.execute('SELECT * FROM delivery_request WHERE request_id=?',
                         (request_id,)).fetchone()
        if not row:
            raise ValueError('unknown_delivery_request')
        # Anonymous numbering mirrors the package: sequential over observable (non-suppressed)
        # classes only. Internal class numbers and subject membership never leave the ledger.
        class_rows = db.execute(
            'SELECT DISTINCT class_no,suppressed FROM delivery_class WHERE request_id=? '
            'ORDER BY class_no', (request_id,)).fetchall()
        anonymous = {}
        cursor = 0
        for cls in class_rows:
            if not cls['suppressed']:
                cursor += 1
                anonymous[cls['class_no']] = cursor
        entries = []
        for r in db.execute(
                'SELECT class_no,prior_request_id,prior_class_no,overlap_count,meets_k,protected '
                'FROM delivery_intersection WHERE request_id=? '
                'ORDER BY protected,class_no,prior_request_id,prior_class_no',
                (request_id,)):
            # Only the anonymous group number leaves the ledger; the internal class number and
            # the subject membership behind it never appear in the public report.
            if r['class_no'] not in anonymous:
                continue
            entries.append({'anonymous_no': anonymous[r['class_no']],
                            'prior_request_id': r['prior_request_id'],
                            'prior_anonymous_no': r['prior_class_no'] + 1,
                            'overlap_count': r['overlap_count'],
                            'meets_k': bool(r['meets_k']),
                            'protected': bool(r['protected'])})
        suppressed = db.execute(
            'SELECT count(DISTINCT subject) FROM delivery_class WHERE request_id=? AND suppressed=1',
            (request_id,)).fetchone()[0]
        return {'request_id': request_id, 'state': row['state'],
                'hold_reason': row['hold_reason'],
                'suppressed_subject_count': suppressed, 'intersections': entries}
    finally:
        db.close()


def verify(db_path, request_id, package_root):
    """Independently recompute provenance, single-package k and cross-package intersections.

    Tampering revokes this request's deliverable conclusion only; older legal packages are never
    rewritten.
    """
    package_root = Path(package_root).resolve()
    db = connect(db_path)
    problems = []
    try:
        db.executescript(SCHEMA)
        from .minimization import SCHEMA as MIN_SCHEMA
        db.executescript(MIN_SCHEMA)
        row = db.execute('SELECT * FROM delivery_request WHERE request_id=?',
                         (request_id,)).fetchone()
        if not row:
            raise ValueError('unknown_delivery_request')
        if row['state'] != 'published':
            return {'request_id': request_id, 'state': row['state'], 'problems': problems}

        target = package_root / request_id
        for name, stored in (('package.json', row['package_hash']),
                             ('proof.json', row['proof_hash'])):
            path = target / name
            if not path.is_file() or \
                    hashlib.sha256(path.read_bytes()).hexdigest() != stored:
                problems.append(f'package_tampered:{name}')
        if problems:
            with db:
                db.execute("UPDATE delivery_request SET state='revoked' WHERE request_id=?",
                           (request_id,))
            return {'request_id': request_id, 'state': 'revoked', 'problems': problems}

        package = json.loads((target / 'package.json').read_text(encoding='utf-8'))
        proof = json.loads((target / 'proof.json').read_text(encoding='utf-8'))
        receipt, inventory_rows, field_index = _load_inventory(db, row['inventory_id'])
        spec = json.loads(row['spec_raw'])
        # Re-hash the original inventory bytes; a moved or rewritten source invalidates the proof.
        source = Path(spec['inventory_csv_path'])
        if not source.is_file() or \
                hashlib.sha256(source.read_bytes()).hexdigest() != receipt['source_hash']:
            problems.append('inventory_source_tampered')
        info = _validate_spec(spec, inventory_rows, field_index)
        info['subjects'] = sorted(r['subject'] for r in db.execute(
            'SELECT subject FROM delivery_pseudo WHERE request_id=?', (request_id,)))
        field_class = _field_classes(inventory_rows)

        # 1. Field provenance.
        for field in info['quasi'] + info['analytic']:
            if 'direct' in field_class[field]:
                problems.append(f'direct_field_leak:{field}')
        for field, inputs in info['lineage'].items():
            for input_field, reversible in inputs:
                if reversible and 'direct' in field_class.get(input_field, set()):
                    problems.append(f'reversible_direct_lineage:{field}')

        # 2. Single-package k-anonymity over the published rows.
        published = package['rows']
        pseudo_to_subject = {r['pseudonym']: r['subject'] for r in db.execute(
            'SELECT subject,pseudonym FROM delivery_pseudo WHERE request_id=?', (request_id,))}
        key_fields = sorted(info['quasi'])
        groups = {}
        for record in published:
            if record['pseudonym'] not in pseudo_to_subject:
                problems.append('unknown_pseudonym')
                continue
            groups.setdefault(tuple(record[f] for f in key_fields), set()).add(
                record['pseudonym'])
        if any(len(v) < row['k_value'] for v in groups.values()):
            problems.append('single_package_k_violated')
        if len(published) + row['max_suppression'] < len(info['subjects']):
            problems.append('suppression_budget_violated')

        # 3. Cross-package intersections from internal identities (this package excluded).
        prior = _prior_classes(db, row['recipient'], exclude_request=request_id)
        published_subjects = {pseudo_to_subject[r['pseudonym']] for r in published}
        for cls in proof['classes']:
            if cls['suppressed']:
                if set(cls['members']) & published_subjects:
                    problems.append(f'suppressed_class_published:{cls["class_no"]}')
                continue
            members = set(cls['members'])
            if not members <= published_subjects:
                problems.append(f'proof_class_mismatch:{cls["class_no"]}')
            if len(members) < row['k_value']:
                problems.append(f'proof_class_below_k:{cls["class_no"]}')
            for prior_id, prior_partition in prior:
                for prior_members in prior_partition:
                    overlap = members & set(prior_members)
                    if overlap and len(overlap) < row['k_value']:
                        problems.append(
                            f'cross_intersection_below_k:{cls["class_no"]}:{prior_id}')

        # 4. The public package must never contain internal subject identifiers.
        if any('subject' in record for record in published):
            problems.append('internal_identity_leaked')
        blob = json.dumps(package, ensure_ascii=False)
        for subject in info['subjects']:
            # Word-boundary match: a value like "city-alpha" must not flag subject "a".
            if re.search(r'(?<![A-Za-z0-9_-])' + re.escape(subject) + r'(?![A-Za-z0-9_-])',
                         blob):
                problems.append('internal_identifier_in_package')
                break

        if problems:
            with db:
                db.execute("UPDATE delivery_request SET state='revoked' WHERE request_id=?",
                           (request_id,))
        return {'request_id': request_id,
                'state': 'revoked' if problems else 'published', 'problems': problems}
    finally:
        db.close()
