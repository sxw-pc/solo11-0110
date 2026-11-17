"""离线“下次应复核时点”预报。

冻结本 run 的政策（配置哈希）、原始事件水位与 as_of，为每个对象给出最早有
依据的复核日期、触发证据与级别（保证到期/有条件/无法预报）。预报只供保管员
安排证据收集，不执行销毁，也不改写任何既有 run 的裁决；重新导入事件或
recheck 只会生成新的预报行。

两个独立合同：

- 审计保证合同（audit）：只输出在当前已冻结证据下不会被未来已知事件推翻的
  保证复核时点，否则为无法预报。起点必须由已发生（<= as_of）的证据确定，
  保全必须已解除，且不允许已知未来事件改变该日期。
- 运营排程合同（operational）：可输出附带明示前提的条件日期（如“之后无新
  use 事件”“保全 X 解除”），供人工复核排程；该日期不是可销毁授权。

时间一律按 retaincase.timeline 的 UTC 归一结果与半开保全区间 [start, end)
计算；未来事件只进入预报，不进入 evaluate 的当前结论。
"""
import hashlib, json
from datetime import timedelta

from .rules import _config, subject_events
from .store import connect
from .timeline import instant, utc_day

AUDIT = 'audit'
OPERATIONAL = 'operational'
CONTRACTS = (AUDIT, OPERATIONAL)
CONTRACT_LABEL = {AUDIT: '审计保证', OPERATIONAL: '运营排程'}
GUARANTEED = '保证到期'
CONDITIONAL = '有条件'
UNKNOWN = '无法预报'
# 政策起点对应的重置事件类型；created 起点固定，不存在重置事件。
_START_EVENT = {'last_use': 'use', 'terminated': 'terminate'}


def _event_ref(event, id_by_key):
    ref = {'event_key': event['event_key'], 'kind': event['kind'], 'at': event.get('at')}
    if event.get('at'):
        ref['utc_day'] = str(utc_day(event['at']))
    row = id_by_key.get(event['event_key'])
    if row is not None:
        ref['event_id'] = row['id']
        ref['source_id'] = row['source_id']
    return ref


def _own_analysis(subject, spec, config, ev, asof, id_by_key):
    """单对象自身证据分析（不含依赖传递）。日期均为 UTC 日。"""
    policy = config['policy'][spec['category']]
    start_kind = policy['start']
    days = policy['days']
    if start_kind not in ('created', 'terminated', 'last_use'):
        raise ValueError('unknown_policy_start')
    asof_day = asof.date()
    own = {'subject': subject, 'category': spec['category'],
           'policy': {'start': start_kind, 'days': days}, 'start_kind': start_kind}
    if start_kind == 'created':
        created = spec.get('created')
        day = utc_day(created) if created else None
        own['start_day_current'] = own['start_day_all'] = day
        own['created_day'] = str(day) if day else None
        own['start_events'] = []
        own['future_start_events'] = []
    else:
        kind = _START_EVENT[start_kind]
        relevant = [e for e in ev if e['kind'] == kind and e.get('at')]
        past = [e for e in relevant if instant(e['at']) <= asof]
        future = [e for e in relevant if instant(e['at']) > asof]
        own['start_day_current'] = max((utc_day(e['at']) for e in past), default=None)
        own['start_day_all'] = max((utc_day(e['at']) for e in relevant), default=None)
        own['created_day'] = None
        own['start_events'] = [_event_ref(e, id_by_key) for e in relevant]
        own['future_start_events'] = [_event_ref(e, id_by_key) for e in future]
    # 保全按半开区间 [start, end) 回放：end 当日即解除。
    open_holds = {}
    intervals = []
    problems = []
    for e in ev:
        if e['kind'] == 'hold_start':
            open_holds[e['hold_id']] = e
        elif e['kind'] == 'hold_end':
            started = open_holds.pop(e['hold_id'], None)
            if started is None:
                problems.append({'code': 'unmatched_hold_release',
                                 'detail': f"保全 {e['hold_id']} 的解除没有对应的开始",
                                 'event_keys': [e['event_key']]})
            else:
                intervals.append({'hold_id': e['hold_id'], 'start': started['at'], 'end': e['at'],
                                  'start_event': started, 'end_event': e})
    for hold_id, started in open_holds.items():
        intervals.append({'hold_id': hold_id, 'start': started['at'], 'end': None,
                          'start_event': started, 'end_event': None})
    own['intervals'] = intervals
    own['problems'] = problems
    own['open_holds'] = [i for i in intervals if i['end'] is None]
    # 未结清的保全：解除日未知，或解除日在 as_of 之后（含未来才开始的保全）。
    own['unsettled_holds'] = [i for i in intervals
                              if i['end'] is None or utc_day(i['end']) > asof_day]
    clear_days = [utc_day(i['end']) for i in intervals if i['end'] is not None]
    own['hold_clear_day'] = max(clear_days) if clear_days else None
    start = own['start_day_all']
    own['expiry_all'] = start + timedelta(days=days) if start else None
    start = own['start_day_current']
    own['expiry_current'] = start + timedelta(days=days) if start else None
    return own


def _dependency_graph(config, merged, asof):
    """与 evaluate 一致的当前依赖图（depends_on 事件 at <= as_of）。"""
    dependencies = {}
    dep_events = {}
    for subject, ev in merged.items():
        for e in ev:
            if e['kind'] == 'depends_on' and e.get('at') and instant(e['at']) <= asof:
                dependencies.setdefault(subject, set()).add(e['parent'])
                dep_events[(subject, e['parent'])] = e
    children_of = {}
    for child, parents in dependencies.items():
        for parent in parents:
            children_of.setdefault(parent, set()).add(child)
    color = {}
    cycle_nodes = set()

    def dfs(node, path):
        color[node] = 1
        path.append(node)
        for parent in dependencies.get(node, ()):
            if parent not in config['subjects']:
                continue
            if color.get(parent, 0) == 1:
                cycle_nodes.update(path[path.index(parent):])
            elif color.get(parent, 0) == 0:
                dfs(parent, path)
        path.pop()
        color[node] = 2

    for node in list(dependencies):
        if color.get(node, 0) == 0:
            dfs(node, [])
    return dependencies, dep_events, children_of, cycle_nodes


def _basis(own):
    return {'policy': own['policy'], 'category': own['category'],
            'created_day': own['created_day'],
            'start_day_current': str(own['start_day_current']) if own['start_day_current'] else None,
            'start_day_all': str(own['start_day_all']) if own['start_day_all'] else None,
            'start_events': own['start_events'],
            'future_start_events': own['future_start_events'],
            'holds': [{'hold_id': i['hold_id'], 'start': i['start'], 'end': i['end'],
                       'start_event_key': i['start_event']['event_key'],
                       'end_event_key': i['end_event']['event_key'] if i['end_event'] else None}
                      for i in own['intervals']]}


def _own_operational(own):
    """运营排程合同：自身最早有依据的复核日期，前提明示。不含依赖传递。"""
    if own['problems']:
        return {'ok': False, 'blocking': list(own['problems'])}
    if own['start_day_all'] is None:
        kind = own['start_kind']
        if kind == 'created':
            detail = '配置缺 created 起点'
        elif kind == 'terminated':
            detail = '没有 terminate 起点事件，且不从 created 日期猜测'
        else:
            detail = '没有 use 起点事件'
        return {'ok': False, 'blocking': [{'code': 'no_start_evidence', 'detail': detail, 'event_keys': []}]}
    date = own['expiry_all']
    if own['hold_clear_day'] and own['hold_clear_day'] > date:
        date = own['hold_clear_day']
    premises = []
    if own['start_kind'] in _START_EVENT:
        premises.append(f"之后无新 {_START_EVENT[own['start_kind']]} 事件")
    for hold in own['open_holds']:
        premises.append(f"保全 {hold['hold_id']} 解除")
    return {'ok': True, 'date': date, 'premises': premises, 'blocking': []}


def _own_audit(own):
    """审计保证合同：只接受已发生证据确定、且不被未来已知事件推翻的日期。"""
    if own['problems']:
        return {'ok': False, 'blocking': list(own['problems'])}
    if own['start_day_current'] is None:
        kind = own['start_kind']
        if kind == 'created':
            detail = '配置缺 created 起点'
        elif kind == 'terminated':
            detail = '截至 as_of 没有 terminate 起点事件，且不从 created 日期猜测'
        else:
            detail = '截至 as_of 没有 use 起点事件'
        return {'ok': False, 'blocking': [{'code': 'no_start_evidence', 'detail': detail, 'event_keys': []}]}
    if own['unsettled_holds']:
        hold = own['unsettled_holds'][0]
        return {'ok': False, 'blocking': [
            {'code': 'hold_not_released',
             'detail': f"保全 {hold['hold_id']} 未解除，不得凭期限届满给出保证日期",
             'event_keys': [hold['start_event']['event_key']]}]}
    if own['future_start_events']:
        keys = sorted(e['event_key'] for e in own['future_start_events'])
        return {'ok': False, 'blocking': [
            {'code': 'future_start_event',
             'detail': '已知未来起点事件会推迟复核日期，当前证据下无法给出保证时点',
             'event_keys': keys}]}
    date = own['expiry_current']
    if own['hold_clear_day'] and own['hold_clear_day'] > date:
        date = own['hold_clear_day']
    return {'ok': True, 'date': date, 'premises': [], 'blocking': []}


def _combine(subject, own_part, contract, ctx, recurse):
    """把自身结论与依赖子对象合并：子对象仍须保留的最晚日期约束源对象。

    环或缺失父对象给出无法预报并列出阻断证据，不做反复传播得出伪日期。
    """
    config = ctx['config']
    blocking = list(own_part['blocking'])
    ok = own_part['ok']
    missing = sorted(p for p in ctx['dependencies'].get(subject, ()) if p not in config['subjects'])
    if missing:
        keys = sorted(ctx['dep_events'][(subject, p)]['event_key'] for p in missing)
        blocking.append({'code': 'missing_dependency',
                         'detail': f"父对象缺失：{'、'.join(missing)}", 'event_keys': keys})
        ok = False
    if subject in ctx['cycle_nodes']:
        keys = sorted(e['event_key'] for (c, p), e in ctx['dep_events'].items()
                      if c in ctx['cycle_nodes'] and p in ctx['cycle_nodes'])
        blocking.append({'code': 'dependency_cycle', 'detail': '依赖环阻断预报', 'event_keys': keys})
        ok = False
    date = own_part.get('date') if ok else None
    date = str(date) if date else None
    premises = list(own_part.get('premises', [])) if ok else []
    chain = []
    child_results = {}
    if ok:
        for child in sorted(ctx['children_of'].get(subject, ())):
            if child not in config['subjects']:
                continue
            result = recurse(child)
            child_results[child] = result
            chain.append({'child': child, 'parent': subject,
                          'via_event': ctx['dep_events'][(child, subject)]['event_key'],
                          'child_level': result['level'], 'child_review_date': result['review_date']})
            chain.extend(result['dependency_chain'])
        unresolved = sorted(c for c, r in child_results.items() if r['level'] == UNKNOWN)
        if unresolved:
            for child in unresolved:
                blocking.append({'code': 'dependent_unresolved',
                                 'detail': f"子对象 {child} 无法预报，源对象日期无法确定",
                                 'event_keys': [ctx['dep_events'][(child, subject)]['event_key']]})
            ok = False
    if ok:
        for child, result in child_results.items():
            if result['review_date'] and (date is None or result['review_date'] > date):
                date = result['review_date']
            for premise in result['premises']:
                if premise not in premises:
                    premises.append(premise)
    seen = set()
    deduped = []
    for edge in chain:
        key = (edge['child'], edge['parent'], edge['via_event'])
        if key not in seen:
            seen.add(key)
            deduped.append(edge)
    if not ok:
        return {'level': UNKNOWN, 'review_date': None, 'premises': [],
                'blocking': blocking, 'dependency_chain': deduped, 'basis': ctx['basis'][subject]}
    level = CONDITIONAL if (contract == OPERATIONAL and premises) else GUARANTEED
    return {'level': level,
            'review_date': date,
            'premises': premises, 'blocking': [],
            'dependency_chain': deduped, 'basis': ctx['basis'][subject]}


def _compute(config, events):
    asof = instant(config['as_of'])
    merged, _grouped = subject_events(config, events)
    id_by_key = {e['event_key']: e for e in events}
    own_map = {s: _own_analysis(s, spec, config, merged[s], asof, id_by_key)
               for s, spec in config['subjects'].items()}
    dependencies, dep_events, children_of, cycle_nodes = _dependency_graph(config, merged, asof)
    ctx = {'config': config, 'dependencies': dependencies, 'dep_events': dep_events,
           'children_of': children_of, 'cycle_nodes': cycle_nodes,
           'basis': {s: _basis(own) for s, own in own_map.items()}}
    results = {}
    for contract in CONTRACTS:
        own_parts = {s: (_own_operational(own) if contract == OPERATIONAL else _own_audit(own))
                     for s, own in own_map.items()}
        memo = {}

        def recurse(subject, contract=contract):
            if subject not in memo:
                memo[subject] = _combine(subject, own_parts[subject], contract, ctx, recurse)
            return memo[subject]

        for subject in config['subjects']:
            results.setdefault(subject, {})[contract] = recurse(subject)
    return results, asof


def forecast(path, contract=None):
    """生成并持久化一次预报；返回本次预报内容。只插入新行，不改写旧预报。"""
    if contract is not None and contract not in CONTRACTS:
        raise ValueError('unknown_contract')
    db = connect(path)
    config = _config(db)
    frozen = db.execute('SELECT config_raw, config_hash FROM batch WHERE id=?',
                        (config['batch_id'],)).fetchone()
    if hashlib.sha256(frozen['config_raw']).hexdigest() != frozen['config_hash']:
        raise ValueError('batch_config_tampered')
    events = [dict(r) for r in db.execute('SELECT * FROM raw_event ORDER BY at,id')]
    results, _asof = _compute(config, events)
    run = db.execute('SELECT max(id) AS m FROM run').fetchone()['m']
    decisions = {}
    if run is not None:
        decisions = {r['subject']: r['status'] for r in
                     db.execute('SELECT subject,status FROM decision WHERE run_id=?', (run,))}
    watermark = {'count': len(events),
                 'max_id': max((e['id'] for e in events), default=0),
                 'digest': hashlib.sha256(
                     ','.join(sorted(e['digest'] for e in events)).encode()).hexdigest()}
    contracts = (contract,) if contract else CONTRACTS
    with db:
        forecast_run = db.execute(
            'INSERT INTO forecast_run(batch_id,run_id,as_of,rule_version,config_hash,watermark)'
            ' VALUES (?,?,?,?,?,?)',
            (config['batch_id'], run, config['as_of'], config['rule_version'],
             frozen['config_hash'], json.dumps(watermark, sort_keys=True))).lastrowid
        for subject in config['subjects']:
            for name in contracts:
                result = results[subject][name]
                detail = {'contract': name, 'contract_label': CONTRACT_LABEL[name],
                          'as_of': config['as_of'], 'rule_version': config['rule_version'],
                          'level': result['level'], 'review_date': result['review_date'],
                          'premises': result['premises'], 'basis': result['basis'],
                          'blocking': result['blocking'],
                          'dependency_chain': result['dependency_chain'],
                          'current_decision': decisions.get(subject),
                          'watermark': watermark,
                          'note': '仅供人工安排复核与证据收集，不构成可销毁授权'}
                db.execute(
                    'INSERT INTO forecast(forecast_run_id,subject,contract,level,review_date,premises,detail)'
                    ' VALUES (?,?,?,?,?,?,?)',
                    (forecast_run, subject, name, result['level'], result['review_date'],
                     json.dumps(result['premises'], ensure_ascii=False),
                     json.dumps(detail, ensure_ascii=False, sort_keys=True)))
    db.close()
    return {'forecast_run': forecast_run, 'batch_id': config['batch_id'],
            'as_of': config['as_of'], 'rule_version': config['rule_version'],
            'anchored_run': run, 'watermark': watermark,
            'subjects': {s: {c: results[s][c] for c in contracts} for s in config['subjects']}}
