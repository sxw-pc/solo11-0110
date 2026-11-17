import json
from pathlib import Path
from .store import connect
from .rules import recompute_frozen

VERDICT_LABELS={'verified':'历史自洽','history_distorted':'历史失真','stale':'现时过期','unverifiable':'无法验证'}
CONTRACT_LABELS={'historical':'历史真实性合同','current':'现时可用性合同'}
AUTHORIZATION_NOTICE='verification_is_not_destruction_authorization:验真结论不构成新的销毁授权'

def export(db_path,out):
    db=connect(db_path);out=Path(out);out.parent.mkdir(parents=True,exist_ok=True)
    run=db.execute('SELECT * FROM run ORDER BY id DESC LIMIT 1').fetchone()
    if not run:raise ValueError('no_run')
    rid=run['id'];data={'run':dict(run),'sources':[{'id':x['id'],'name':x['name'],'digest':x['digest']} for x in db.execute('SELECT * FROM source_file ORDER BY id')],
      'decisions':[dict(x) for x in db.execute('SELECT * FROM decision WHERE run_id=? ORDER BY subject',(rid,))],
      'issues':[dict(x) for x in db.execute('SELECT * FROM issue WHERE run_id=? OR run_id IS NULL ORDER BY id',(rid,))],
      'evidence':[dict(x) for x in db.execute('SELECT * FROM evidence WHERE run_id=? ORDER BY id',(rid,))]}
    data['executions']=[dict(x) for x in db.execute('SELECT * FROM execution ORDER BY id')]
    out.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    md=out.with_suffix('.md');md.write_text('# 离线判定报告\n\n'+f'运行 {rid}：{run["status"]}\n\n'+'\n'.join(f'- {x["subject"]}: {x["status"]}，{x["detail"]}' for x in data['decisions']),encoding='utf-8')
    db.close();return out

def verify(db_path):
    db=connect(db_path);problems=[]
    from .ingest import hash_bytes
    for batch in db.execute('SELECT id,config_raw,config_hash FROM batch'):
        if hash_bytes(batch['config_raw'])!=batch['config_hash']:
            problems.append(f'batch_config:{batch["id"]}')
    sources={s['id']:dict(s) for s in db.execute('SELECT * FROM source_file')}
    for s in sources.values():
        from .ingest import hash_bytes
        if hash_bytes(s['raw'])!=s['digest']:problems.append(f'source:{s["id"]}')
    events={e['id']:dict(e) for e in db.execute('SELECT * FROM raw_event')}
    for e in events.values():
        try:
            lines=sources[e['source_id']]['raw'].decode('utf-8-sig').splitlines()
            original=lines[e['line_no']-1]
            if hash_bytes(original.encode('utf-8'))!=e['digest'] or json.loads(original)!=json.loads(e['payload']):
                problems.append(f'event:{e["id"]}')
        except (KeyError,IndexError,UnicodeError,ValueError):
            problems.append(f'event:{e["id"]}')
    for ev in db.execute('SELECT * FROM evidence WHERE event_id IS NOT NULL'):
        source_event=events.get(ev['event_id'])
        if not source_event or source_event['source_id']!=ev['source_id']:
            problems.append(f'evidence:{ev["id"]}')
    for d in db.execute('SELECT * FROM decision'):
        if not db.execute('SELECT 1 FROM evidence WHERE run_id=? AND subject=?',(d['run_id'],d['subject'])).fetchone():problems.append(f'decision:{d["id"]}')
        # Run-scoped: a subject only needs event evidence if that run actually
        # evaluated events for it -- a subject first seen in later runs must not
        # taint an older run whose frozen input legitimately contained none.
        has_inputs=db.execute('SELECT 1 FROM run_input_event WHERE run_id=? AND subject=?',(d['run_id'],d['subject'])).fetchone()
        legacy_no_freeze=not db.execute('SELECT 1 FROM run_input WHERE run_id=?',(d['run_id'],)).fetchone()
        if has_inputs and not db.execute(
            'SELECT 1 FROM evidence WHERE run_id=? AND subject=? AND event_id IS NOT NULL',(d['run_id'],d['subject'])).fetchone():
            problems.append(f'decision_source:{d["id"]}')
        elif legacy_no_freeze and db.execute('SELECT 1 FROM raw_event WHERE subject=?',(d['subject'],)).fetchone() and not db.execute(
            'SELECT 1 FROM evidence WHERE run_id=? AND subject=? AND event_id IS NOT NULL',(d['run_id'],d['subject'])).fetchone():
            problems.append(f'decision_source:{d["id"]}')
    db.close();return problems

def _dependency_chains(edges,subject,dep_events):
    """Subject -> parent chains through the frozen dependency graph, annotated
    with the depends_on source rows that propagate each retention obligation."""
    adj={}
    for child,parent in edges:adj.setdefault(child,[]).append(parent)
    chains=[]
    def walk(node,path):
        parents=adj.get(node)
        if not parents:
            chains.append(list(path));return
        for parent in parents:
            edge=dep_events.get((node,parent))
            step={'child':node,'parent':parent}
            if edge:step.update({'event_key':edge['event_key'],'source_id':edge['source_id'],'line_no':edge['line_no']})
            walk(parent,path+[step])
    walk(subject,[])
    return chains

def _raw_lines(db,event_ids):
    rows=[]
    for eid in sorted(event_ids):
        e=db.execute('SELECT id,source_id,line_no,event_key,subject,kind,at FROM raw_event WHERE id=?',(eid,)).fetchone()
        if not e:
            rows.append({'event_id':eid,'missing':True});continue
        src=db.execute('SELECT raw FROM source_file WHERE id=?',(e['source_id'],)).fetchone()
        line=''
        if src:
            try:line=src['raw'].decode('utf-8-sig').splitlines()[e['line_no']-1]
            except IndexError:line=''
        rows.append({'event_id':e['id'],'source_id':e['source_id'],'line_no':e['line_no'],
                     'event_key':e['event_key'],'subject':e['subject'],'kind':e['kind'],
                     'at':e['at'],'raw_line':line})
    return rows

def _chain_problems_for_run(db,db_path,run_id):
    """Generic byte-level integrity problems, filtered to the evidence the run
    rests on. A broken source chain can never be explained away as staleness.
    Runs without frozen inputs cannot be scoped and are handled separately."""
    if not db.execute('SELECT 1 FROM run_input WHERE run_id=?',(run_id,)).fetchone():
        return []
    touched_events={r['event_id'] for r in db.execute(
        'SELECT DISTINCT event_id FROM run_input_event WHERE run_id=?',(run_id,)) if r['event_id'] is not None}
    touched_sources={r['source_id'] for r in db.execute(
        'SELECT DISTINCT source_id FROM run_input_event WHERE run_id=?',(run_id,))}
    run_evidence={r['id'] for r in db.execute('SELECT id FROM evidence WHERE run_id=?',(run_id,))}
    run_decisions={r['id'] for r in db.execute('SELECT id FROM decision WHERE run_id=?',(run_id,))}
    relevant=[]
    batch=db.execute('SELECT batch_id FROM run WHERE id=?',(run_id,)).fetchone()
    for problem in verify(db_path):
        kind,_,ref=problem.partition(':')
        ref=int(ref) if ref.isdigit() else ref
        if kind=='event' and ref in touched_events:relevant.append(problem)
        elif kind=='source' and ref in touched_sources:relevant.append(problem)
        elif kind=='evidence' and ref in run_evidence:relevant.append(problem)
        elif kind in ('decision','decision_source') and ref in run_decisions:relevant.append(problem)
        elif kind=='batch_config' and batch and ref==batch['batch_id']:relevant.append(problem)
    return sorted(set(relevant))

def _compare_run(db,run_id,recomputed,policy_digest):
    """Item-by-item comparison of stored decision/issue/evidence against the
    isolated recomputation, with raw lines and dependency propagation paths."""
    stored_decisions={r['subject']:r['status'] for r in db.execute(
        'SELECT subject,status FROM decision WHERE run_id=?',(run_id,))}
    stored_issues={}
    for r in db.execute('SELECT subject,code FROM issue WHERE run_id=? ORDER BY subject,code',(run_id,)):
        stored_issues.setdefault(r['subject'],[]).append(r['code'])
    stored_membership={}
    for r in db.execute("""SELECT subject,event_id FROM evidence
                           WHERE run_id=? AND event_id IS NOT NULL ORDER BY subject,event_id""",(run_id,)):
        stored_membership.setdefault(r['subject'],[]).append(r['event_id'])
    dep_events={}
    for e in db.execute("SELECT subject,payload,source_id,line_no FROM raw_event WHERE kind='depends_on'"):
        item=json.loads(e['payload']);dep_events[(e['subject'],item['parent'])]={
            'event_key':item['event_key'],'source_id':e['source_id'],'line_no':e['line_no']}
    mismatches=[]
    subjects=sorted(set(stored_decisions)|set(recomputed['decision']))
    for subject in subjects:
        subject_mismatch=None
        if stored_decisions.get(subject)!=recomputed['decision'].get(subject):
            subject_mismatch={'subject':subject,'field':'decision.status',
                              'stored':stored_decisions.get(subject),
                              'recomputed':recomputed['decision'].get(subject)}
        elif sorted(stored_issues.get(subject,[]))!=sorted(recomputed['issues'].get(subject,[])):
            subject_mismatch={'subject':subject,'field':'issue.codes',
                              'stored':sorted(stored_issues.get(subject,[])),
                              'recomputed':sorted(recomputed['issues'].get(subject,[]))}
        elif sorted(stored_membership.get(subject,[]))!=sorted(recomputed['membership'].get(subject,[])):
            subject_mismatch={'subject':subject,'field':'evidence.events',
                              'stored':sorted(stored_membership.get(subject,[])),
                              'recomputed':sorted(recomputed['membership'].get(subject,[]))}
        if subject_mismatch:
            ids=sorted(set(stored_membership.get(subject,[]))|set(recomputed['membership'].get(subject,[])))
            subject_mismatch['policy_digest']=policy_digest
            subject_mismatch['raw_lines']=_raw_lines(db,ids)
            subject_mismatch['dependency_paths']=_dependency_chains(recomputed['dependency_edges'],subject,dep_events)
            mismatches.append(subject_mismatch)
    return mismatches

def verify_run(db_path,run_id,*,persist=True):
    """Independent verification of one historical run under two contracts.

    历史真实性合同: recompute conclusions, issue codes and dependency-propagated
    evidence in an isolated copy from the run's own frozen policy bytes and event
    watermark, then compare item by item with what was stored. Missing frozen
    evidence is 'unverifiable' -- present state is never used to fabricate past
    proof. 现时可用性合同 additionally requires agreement with the latest
    supplemented evidence, preservation holds and policy; disagreement is
    'stale' and never retroactively labelled an original error. A tampered
    decision row is 'history_distorted' under both contracts.
    """
    db=connect(db_path)
    run=db.execute('SELECT * FROM run WHERE id=?',(run_id,)).fetchone()
    if not run:
        db.close();raise ValueError('unknown_run')
    frozen=db.execute('SELECT * FROM run_input WHERE run_id=?',(run_id,)).fetchone()
    chain_problems=_chain_problems_for_run(db,str(db_path),run_id)
    historical={'contract':'historical','label':CONTRACT_LABELS['historical'],
                'reasons':sorted(chain_problems and ['source_chain_tampered'] or []),
                'chain_problems':chain_problems,
                'policy_digest':frozen['config_hash'] if frozen else None,
                'event_watermark':frozen['event_watermark'] if frozen else None,
                'input_digest':frozen['input_digest'] if frozen else None,
                'mismatches':[]}
    current={'contract':'current','label':CONTRACT_LABELS['current'],'reasons':[],
             'mismatches':[],'new_events':[],'current_policy_digest':None}
    if not frozen:
        historical['verdict']='unverifiable';historical['reasons'].append('no_frozen_input')
        current['verdict']='unverifiable';current['reasons'].append('no_frozen_input')
    else:
        # Byte-level tampering of source/event/policy bytes makes recomputation
        # unsafe and establishes distortion on its own. Deleted evidence rows do
        # not poison the engine, so they still get full item-level mismatches.
        byte_chain=[p for p in chain_problems if not (p.startswith('evidence:') or p.startswith('decision'))]
        row_chain=[p for p in chain_problems if p.startswith(('evidence:','decision'))]
        if byte_chain:
            historical['verdict']='history_distorted'
            current['verdict']='history_distorted'
            current['reasons']=list(historical['reasons'])
        else:
            if row_chain:historical['reasons'].append('stored_row_tampered')
            recomputed=recompute_frozen(db_path,run_id,mode='frozen')
            if recomputed['stored_input_digest']!=frozen['input_digest']:
                historical['reasons'].append('freeze_membership_tampered')
            from .ingest import hash_bytes
            if hash_bytes(frozen['config_raw'])!=frozen['config_hash']:
                historical['reasons'].append('freeze_policy_tampered')
            historical['mismatches']=_compare_run(db,run_id,recomputed,frozen['config_hash'])
            if historical['reasons'] or historical['mismatches']:
                historical['verdict']='history_distorted'
                if not historical['reasons']:historical['reasons'].append('recomputed_mismatch')
            else:
                historical['verdict']='verified'
            # Current-usability contract only gets its own findings when history is
            # intact; distortion/unverifiability dominates and must not be relabelled
            # as mere staleness.
            if historical['verdict']!='verified':
                current['verdict']=historical['verdict']
                current['reasons']=list(historical['reasons'])
                current['mismatches']=historical['mismatches']
            else:
                present=recompute_frozen(db_path,run_id,mode='current')
                batch=db.execute('SELECT config_hash FROM batch WHERE id=?',(run['batch_id'],)).fetchone()
                current['current_policy_digest']=batch['config_hash']
                current['mismatches']=_compare_run(db,run_id,present,batch['config_hash'])
                current['new_events']=[dict(r) for r in db.execute(
                    'SELECT id,source_id,line_no,event_key,subject,kind,at FROM raw_event WHERE id>? ORDER BY id',
                    (frozen['event_watermark'],))]
                if batch['config_hash']!=frozen['config_hash']:current['reasons'].append('policy_revised')
                if current['new_events']:current['reasons'].append('events_supplemented')
                current['reasons'].append('recomputed_drift') if current['mismatches'] else None
                current['verdict']='stale' if current['reasons'] else 'verified'
    result={'run_id':run_id,'run_status':run['status'],
            'historical':historical,'current':current,
            'authorization_notice':AUTHORIZATION_NOTICE}
    for contract in ('historical','current'):
        verdict=result[contract]['verdict']
        result[contract]['verdict_label']=VERDICT_LABELS[verdict]
        if persist:
            db.execute('INSERT INTO run_verification(run_id,contract,verdict,input_digest,detail) VALUES (?,?,?,?,?)',
                       (run_id,contract,verdict,result[contract].get('input_digest'),
                        json.dumps(result[contract],ensure_ascii=False,sort_keys=True)))
    if persist:db.commit()
    db.close();return result

def write_verification_report(result,out):
    out=Path(out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    lines=[f'# 运行 {result["run_id"]} 独立验真报告','']
    for contract in ('historical','current'):
        block=result[contract]
        lines.append(f'## {block["label"]}：{block["verdict_label"]}（{block["verdict"]}）')
        if block['reasons']:lines.append('原因：'+', '.join(block['reasons']))
        for m in block['mismatches']:
            lines.append(f'- 主体 {m["subject"]} 字段 {m["field"]}：存储={m["stored"]} 重算={m["recomputed"]}，政策摘要={m["policy_digest"]}')
            for raw in m['raw_lines']:
                if raw.get('missing'):lines.append(f'  - 原始行缺失：event_id={raw["event_id"]}')
                else:lines.append(f'  - 原始行 source={raw["source_id"]} line={raw["line_no"]} key={raw["event_key"]} kind={raw["kind"]}：{raw["raw_line"]}')
            for path in m['dependency_paths']:
                if not path:continue
                text=' -> '.join(f"{step['child']}依赖{step['parent']}" +(f"[{step.get('event_key')}@source{step.get('source_id')}:{step.get('line_no')}]" if step.get('event_key') else '') for step in path)
                lines.append(f'  - 依赖传递路径：{text}')
        if contract=='current' and block.get('new_events'):
            lines.append('- 补录事件：'+', '.join(f"{e['event_key']}(id={e['id']})" for e in block['new_events']))
        lines.append('')
    lines.append('> '+AUTHORIZATION_NOTICE)
    out.with_suffix('.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    return out
