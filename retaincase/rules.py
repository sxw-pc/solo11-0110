import json,hashlib,tempfile,sqlite3
from datetime import timedelta
from pathlib import Path
from .store import connect
from .timeline import instant,utc_day

def _config(db):return json.loads(db.execute('SELECT config_raw FROM batch LIMIT 1').fetchone()[0])

def input_digest(config_hash,event_watermark,membership):
    """Canonical digest of the exact decision inputs: frozen policy bytes + event
    high-water mark + per-subject participating event identity."""
    payload={'config_hash':config_hash,'event_watermark':event_watermark,
             'membership':{s:sorted(ids) for s,ids in sorted(membership.items())}}
    return hashlib.sha256(json.dumps(payload,sort_keys=True,ensure_ascii=False).encode('utf-8')).hexdigest()

def compute_decisions(config,events):
    """Pure rule engine.

    ``events`` are raw_event rows (dicts including id/source_id/line_no) ordered
    by (at,id). Only the rows passed in participate, so a frozen watermark can be
    recomputed without any event ingested afterwards.
    Returns decision status, issue codes, participating rows per subject and the
    dependency edge list -- nothing here reads or writes a database.
    """
    grouped={s:[] for s in config['subjects']}
    for e in events:grouped[e['subject']].append(json.loads(e['payload']))
    asof=instant(config['as_of']);decision={};issues={};dependencies={}
    all_events=[json.loads(e['payload']) for e in events]
    event_by_key={json.loads(e['payload'])['event_key']:e for e in events}
    used_events={}
    for subject,spec in config['subjects'].items():
        ev=grouped[subject]+[e for e in all_events if e.get('scope_tag') in spec.get('tags',[]) and e['subject']!=subject and e['kind'] in ('hold_start','hold_end')]
        ev=sorted(ev,key=lambda e:(instant(e['at']) if e.get('at') else asof,e['event_key']))
        used_events[subject]=[event_by_key[e['event_key']] for e in ev]
        codes=[];start_kind=config['policy'][spec['category']]['start']
        if start_kind=='created':start=spec.get('created')
        elif start_kind=='terminated':
            ends=[e['at'] for e in ev if e['kind']=='terminate' and e.get('at') and instant(e['at'])<=asof]
            start=max(ends,key=instant) if ends else None
        elif start_kind=='last_use':
            uses=[e['at'] for e in ev if e['kind']=='use' and e.get('at') and instant(e['at'])<=asof]
            start=max(uses,key=instant) if uses else None
        else:raise ValueError('unknown_policy_start')
        if not start:codes.append('evidence_gap')
        holds={};active=[]
        for e in ev:
            if e['kind']=='hold_start' and instant(e['at'])<=asof:holds[e['hold_id']]=e['at']
            if e['kind']=='hold_end' and instant(e['at'])<=asof:
                if e['hold_id'] not in holds:codes.append('unmatched_hold_release')
                else:holds.pop(e['hold_id'])
            if e['kind']=='depends_on' and instant(e['at'])<=asof:dependencies.setdefault(subject,set()).add(e['parent'])
        active=list(holds)
        if start and utc_day(start)+timedelta(days=config['policy'][spec['category']]['days'])>asof.date():codes.append('not_expired')
        if active:codes.append('legal_hold')
        decision[subject]='证据不足' if {'evidence_gap','unmatched_hold_release'} & set(codes) else ('冻结' if codes else '可销毁');issues[subject]=codes
    visiting=set();visited=set();cycles=set()
    def visit(node):
        if node in visiting:cycles.update(visiting);return
        if node in visited:return
        visiting.add(node)
        for parent in dependencies.get(node,set()):visit(parent)
        visiting.remove(node);visited.add(node)
    for node in dependencies:visit(node)
    for node in cycles:
        if node in decision:decision[node]='证据不足';issues[node].append('dependency_cycle')
    changed=True
    for _ in range(len(decision)+1):
        if not changed:break
        changed=False
        for child,parents in dependencies.items():
            for parent in parents:
                if parent not in decision:
                    issues[child].append('missing_dependency');decision[child]='证据不足';continue
                if decision[child]!='可销毁' and decision[parent]=='可销毁':decision[parent]='冻结';issues[parent].append('dependent_retained');changed=True
    else:
        for child in dependencies:decision[child]='证据不足';issues[child].append('dependency_cycle')
    # A retained descendant is evidence for every ancestor it keeps alive. Carry
    # its source events through the dependency graph so the parent's proof can
    # be reconstructed without trusting a summary string.
    for _ in range(len(decision)):
        changed=False
        for child,parents in dependencies.items():
            for parent in parents:
                if parent not in used_events:continue
                known={e['id'] for e in used_events[parent]}
                added=[e for e in used_events[child] if e['id'] not in known]
                if added:used_events[parent].extend(added);changed=True
        if not changed:break
    membership={s:[e['id'] for e in rows] for s,rows in used_events.items() if rows}
    edges=sorted((child,parent) for child,parents in dependencies.items() for parent in parents)
    return {'decision':decision,'issues':{s:sorted(set(c)) for s,c in issues.items()},
            'used_events':used_events,'membership':membership,'dependency_edges':edges}

def _persist_run(db,config,result):
    """Write run/issue/evidence/decision plus the frozen inputs in one transaction."""
    run=db.execute("INSERT INTO run(batch_id,status) VALUES (?, '待接收')",(config['batch_id'],)).lastrowid
    db.execute("UPDATE run SET status='已校验' WHERE id=?",(run,))
    participating={i for ids in result['membership'].values() for i in ids}
    grouped={s:[] for s in config['subjects']}
    for e in db.execute('SELECT * FROM raw_event ORDER BY at,id'):
        if e['id'] in participating:
            grouped[e['subject']].append(json.loads(e['payload']))
    for subject,status in result['decision'].items():
        for code in result['issues'][subject]:
            db.execute('INSERT INTO issue(run_id,subject,code,detail) VALUES (?,?,?,?)',(run,subject,code,code))
        ev=grouped[subject];detail=json.dumps({'events':ev,'event_ids':sorted(e['id'] for e in result['used_events'][subject]),
                                               'rules':config['rule_version'],'issues':result['issues'][subject]},ensure_ascii=False)
        db.execute('INSERT INTO evidence(run_id,subject,rule_id,detail) VALUES (?,?,?,?)',(run,subject,config['rule_version'],detail))
        for event in result['used_events'][subject]:
            db.execute('INSERT INTO evidence(run_id,subject,source_id,event_id,rule_id,detail) VALUES (?,?,?,?,?,?)',
                       (run,subject,event['source_id'],event['id'],config['rule_version'],'decision_input'))
        db.execute('INSERT INTO decision(run_id,subject,status,detail) VALUES (?,?,?,?)',(run,subject,status,detail))
    # Freeze the exact inputs this run was derived from: policy bytes, the raw
    # event high-water mark actually evaluated, and every event each subject
    # participated in (including dependency-propagated source rows).
    config_raw=db.execute('SELECT config_raw,config_hash FROM batch WHERE id=?',(config['batch_id'],)).fetchone()
    watermark=db.execute('SELECT max(id) FROM raw_event').fetchone()[0]
    watermark=watermark or 0
    digest=input_digest(config_raw['config_hash'],watermark,result['membership'])
    db.execute('INSERT INTO run_input(run_id,config_hash,config_raw,event_watermark,input_digest) VALUES (?,?,?,?,?)',
               (run,config_raw['config_hash'],config_raw['config_raw'],watermark,digest))
    for subject,ids in sorted(result['membership'].items()):
        for event_id in sorted(ids):
            row=db.execute('SELECT source_id,line_no FROM raw_event WHERE id=?',(event_id,)).fetchone()
            db.execute('INSERT INTO run_input_event(run_id,subject,event_id,source_id,line_no) VALUES (?,?,?,?,?)',
                       (run,subject,event_id,row['source_id'],row['line_no']))
    db.execute("UPDATE run SET status=CASE WHEN EXISTS(SELECT 1 FROM decision WHERE run_id=? AND status='证据不足') THEN '待核' ELSE '已判定' END,ended_at=CURRENT_TIMESTAMP WHERE id=?",(run,run))
    return run

def evaluate(path):
    db=connect(path);config=_config(db)
    events=[dict(r) for r in db.execute('SELECT * FROM raw_event ORDER BY at,id')]
    result=compute_decisions(config,events)
    with db:_persist_run(db,config,result)
    db.close();return result['decision']

def recompute_frozen(db_path,run_id,*,mode):
    """Recompute a run's conclusions in an isolated copy from frozen inputs.

    mode='frozen' uses only the policy bytes and event watermark captured by the
    run, so later ingested events or policy revisions cannot leak into history.
    mode='current' uses the present full event set and present policy bytes --
    the input for the current-usability contract, never a historical proof.
    Does not write anything to the source database.
    """
    if mode not in ('frozen','current'):raise ValueError('unknown_recompute_mode')
    source=connect(db_path)
    run=source.execute('SELECT * FROM run WHERE id=?',(run_id,)).fetchone()
    if not run:
        source.close();raise ValueError('unknown_run')
    frozen=source.execute('SELECT * FROM run_input WHERE run_id=?',(run_id,)).fetchone()
    if mode=='frozen' and not frozen:
        source.close()
        return {'mode':mode,'run_id':run_id,'available':False,
                'reason':'no_frozen_input','decision':{},'issues':{},
                'membership':{},'dependency_edges':[],'config_hash':None,
                'event_watermark':None,'input_digest':None}
    with tempfile.TemporaryDirectory() as tmp:
        copy=Path(tmp)/'recheck.db'
        other=sqlite3.connect(copy)
        source.backup(other)
        other.close();source.close()
        db=connect(copy)
        if mode=='frozen':
            config=json.loads(frozen['config_raw'])
            events=[dict(r) for r in db.execute(
                'SELECT * FROM raw_event WHERE id<=? ORDER BY at,id',(frozen['event_watermark'],))]
            frozen_membership={}
            for row in db.execute('SELECT subject,event_id FROM run_input_event WHERE run_id=? ORDER BY subject,event_id',(run_id,)):
                frozen_membership.setdefault(row['subject'],[]).append(row['event_id'])
            result=compute_decisions(config,events)
            result.update({'mode':mode,'run_id':run_id,'available':True,
                           'config_hash':frozen['config_hash'],
                           'event_watermark':frozen['event_watermark'],
                           'input_digest':frozen['input_digest'],
                           'stored_input_digest':input_digest(
                               frozen['config_hash'],frozen['event_watermark'],frozen_membership),
                           'frozen_membership':{s:sorted(ids) for s,ids in frozen_membership.items()}})
        else:
            batch=db.execute('SELECT config_raw,config_hash FROM batch WHERE id=?',(run['batch_id'],)).fetchone()
            config=json.loads(batch['config_raw'])
            events=[dict(r) for r in db.execute('SELECT * FROM raw_event ORDER BY at,id')]
            result=compute_decisions(config,events)
            result.update({'mode':mode,'run_id':run_id,'available':True,
                           'config_hash':batch['config_hash'],
                           'event_watermark':db.execute('SELECT max(id) FROM raw_event').fetchone()[0] or 0,
                           'input_digest':None})
        db.close()
    return result

def action(command,path,sandbox=None,out=None):
    db=connect(path);config=_config(db)
    if command=='recheck':
        if out:
            raw=Path(out).read_bytes();new=json.loads(raw)
            if new['batch_id']!=config['batch_id'] or new['rule_version']==config['rule_version']:raise ValueError('invalid_rule_revision')
            with db:
                digest=hashlib.sha256(raw).hexdigest()
                db.execute('INSERT INTO rule_version VALUES (?,?,?)',(new['rule_version'],json.dumps(new,sort_keys=True),digest))
                db.execute('UPDATE batch SET config_raw=?,config_hash=? WHERE id=?',(raw,digest,config['batch_id']))
        db.close();return evaluate(path)
    if command=='plan':
        rows=db.execute('SELECT subject,status FROM decision WHERE run_id=(SELECT max(id) FROM run) ORDER BY subject').fetchall()
        plan=[{'subject':r['subject'],'path':config['subjects'][r['subject']]['path'],'sha256':config['subjects'][r['subject']].get('sha256','')} for r in rows if r['status']=='可销毁']
        deps={}
        for event in db.execute("SELECT subject,payload FROM raw_event WHERE kind='depends_on'"):
            item=json.loads(event['payload']);deps.setdefault(item['parent'],set()).add(event['subject'])
        by_id={item['subject']:item for item in plan};ordered=[];visiting=set();seen=set()
        def visit(subject):
            if subject in visiting:raise ValueError('dependency_cycle')
            if subject in seen:return
            visiting.add(subject)
            for child in sorted(deps.get(subject,())):
                if child in by_id:visit(child)
            visiting.remove(subject);seen.add(subject);ordered.append(by_id[subject])
        for subject in sorted(by_id):visit(subject)
        plan=ordered
        targets=[x['path'] for x in plan]
        if len(set(targets))!=len(targets) or any(Path(x).is_absolute() or '..' in Path(x).parts for x in targets):raise ValueError('unsafe_plan')
        destination=Path(out or 'plan.json');body=json.dumps(plan,ensure_ascii=False,indent=2)
        digest=hashlib.sha256(body.encode('utf-8')).hexdigest()
        with db:
            db.execute('INSERT OR IGNORE INTO plan(run_id,digest,body) VALUES ((SELECT max(id) FROM run),?,?)',(digest,body))
        destination.write_text(body,encoding='utf-8');db.close();return str(destination)
    if command=='execute':
        if not sandbox:raise ValueError('sandbox_required')
        root=Path(sandbox).resolve();root.mkdir(parents=True,exist_ok=True)
        frozen=db.execute('SELECT config_raw,config_hash FROM batch WHERE id=?',(config['batch_id'],)).fetchone()
        if hashlib.sha256(frozen['config_raw']).hexdigest()!=frozen['config_hash']:
            raise ValueError('batch_config_tampered')
        body=Path(out or 'plan.json').read_text(encoding='utf-8')
        digest=hashlib.sha256(body.encode('utf-8')).hexdigest()
        latest=db.execute('SELECT max(id) FROM run').fetchone()[0]
        if not db.execute('SELECT 1 FROM plan WHERE digest=? AND run_id=? AND body=?',(digest,latest,body)).fetchone():
            raise ValueError('plan_not_authorized_for_latest_run')
        plan=json.loads(body);done=[]
        eligible={r['subject'] for r in db.execute("SELECT subject FROM decision WHERE run_id=? AND status='可销毁'",(latest,))}
        if {item['subject'] for item in plan}!=eligible or len(plan)!=len(eligible):
            raise ValueError('plan_decision_mismatch')
        for item in plan:
            spec=config['subjects'].get(item['subject'])
            if not spec or item['path']!=spec['path'] or item['sha256']!=spec.get('sha256',''):
                raise ValueError('plan_config_mismatch')
        for item in plan:
            target=(root/item['path']).resolve()
            if root not in target.parents:raise ValueError('unsafe_path')
            if not target.exists():
                if db.execute('SELECT 1 FROM execution WHERE subject=? AND action=? AND before_hash=?',(item['subject'],'destroy',item['sha256'])).fetchone():continue
                raise ValueError('target_missing')
            raw=target.read_bytes()
            digest=hashlib.sha256(raw).hexdigest()
            if not item['sha256'] or digest!=item['sha256']:raise ValueError('hash_changed')
            target.unlink()
            with db:db.execute('INSERT OR IGNORE INTO execution(run_id,subject,action,before_hash,after_state) VALUES ((SELECT max(id) FROM run),?,?,?,?)',(item['subject'],'destroy',digest,'absent'))
            done.append(item['subject'])
        db.close();return done
    raise ValueError('unsupported_action')

def verify_decisions(path):
    """Independent re-derivation of the latest run from that run's own frozen
    inputs in an isolated copy. Runs predating freeze support cannot be
    re-derived and are reported rather than silently checked against present
    state."""
    db=connect(path)
    latest=db.execute('SELECT max(id) FROM run').fetchone()[0]
    db.close()
    if latest is None:return []
    try:
        result=recompute_frozen(path,latest,mode='frozen')
    except (ValueError,KeyError,json.JSONDecodeError):
        return [f'run_input_chain_tampered:{latest}']
    if not result['available']:return [f'unverifiable_run:{latest}:no_frozen_input']
    live=connect(path)
    old={r['subject']:r['status'] for r in live.execute('SELECT subject,status FROM decision WHERE run_id=?',(latest,))}
    live.close()
    return [f'decision_mismatch:{k}' for k in old.keys()|result['decision'].keys() if old.get(k)!=result['decision'].get(k)]
