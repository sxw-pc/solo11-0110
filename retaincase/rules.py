import json,hashlib
from datetime import date,timedelta
from pathlib import Path
from .store import connect

def _config(db):return json.loads(db.execute('SELECT config_raw FROM batch LIMIT 1').fetchone()[0])
def evaluate(path):
    db=connect(path);config=_config(db);events=[dict(r) for r in db.execute('SELECT * FROM raw_event ORDER BY at,id')]
    grouped={s:[] for s in config['subjects']}
    for e in events:grouped[e['subject']].append(json.loads(e['payload']))
    asof=date.fromisoformat(config['as_of']);decision={};issues={};dependencies={}
    all_events=[json.loads(e['payload']) for e in events]
    for subject,spec in config['subjects'].items():
        ev=grouped[subject]+[e for e in all_events if e.get('scope_tag') in spec.get('tags',[]) and e['subject']!=subject and e['kind'] in ('hold_start','hold_end')]
        ev=sorted(ev,key=lambda e:(e.get('at') or '',e['event_key']))
        codes=[];start=spec.get('created')
        uses=[e['at'] for e in ev if e['kind']=='use' and e.get('at')]
        if config['policy'][spec['category']]['start']=='last_use':
            if uses:start=max(uses)
            else:codes.append('evidence_gap')
        holds={};active=[]
        for e in ev:
            if e['kind']=='hold_start' and e['at']<=config['as_of']:holds[e['hold_id']]=e['at']
            if e['kind']=='hold_end' and e['at']<=config['as_of']:holds.pop(e['hold_id'],None)
            if e['kind']=='depends_on':dependencies.setdefault(subject,set()).add(e['parent'])
        active=list(holds)
        if not start:codes.append('evidence_gap')
        elif date.fromisoformat(start)+timedelta(days=config['policy'][spec['category']]['days'])>asof:codes.append('not_expired')
        if active:codes.append('legal_hold')
        decision[subject]='证据不足' if 'evidence_gap' in codes else ('冻结' if codes else '可销毁');issues[subject]=codes
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
    with db:
        run=db.execute("INSERT INTO run(batch_id,status) VALUES (?, '待接收')",(config['batch_id'],)).lastrowid
        db.execute("UPDATE run SET status='已校验' WHERE id=?",(run,))
        for subject,status in decision.items():
            for code in sorted(set(issues[subject])):db.execute('INSERT INTO issue(run_id,subject,code,detail) VALUES (?,?,?,?)',(run,subject,code,code))
            ev=grouped[subject];detail=json.dumps({'events':ev,'rules':config['rule_version'],'issues':issues[subject]},ensure_ascii=False)
            db.execute('INSERT INTO evidence(run_id,subject,rule_id,detail) VALUES (?,?,?,?)',(run,subject,config['rule_version'],detail))
            db.execute('INSERT INTO decision(run_id,subject,status,detail) VALUES (?,?,?,?)',(run,subject,status,detail))
        db.execute("UPDATE run SET status=CASE WHEN EXISTS(SELECT 1 FROM decision WHERE run_id=? AND status='证据不足') THEN '待核' ELSE '已判定' END,ended_at=CURRENT_TIMESTAMP WHERE id=?",(run,run))
    db.close();return decision

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
        destination=Path(out or 'plan.json');destination.write_text(json.dumps(plan,ensure_ascii=False,indent=2),encoding='utf-8');db.close();return str(destination)
    if command=='execute':
        if not sandbox:raise ValueError('sandbox_required')
        root=Path(sandbox).resolve();root.mkdir(parents=True,exist_ok=True)
        plan=json.loads(Path(out or 'plan.json').read_text(encoding='utf-8'));done=[]
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
    import tempfile,sqlite3
    db=connect(path);old={r['subject']:r['status'] for r in db.execute('SELECT subject,status FROM decision WHERE run_id=(SELECT max(id) FROM run)')}
    with tempfile.TemporaryDirectory() as tmp:
        copy=Path(tmp)/'check.db';other=sqlite3.connect(copy);db.backup(other);other.close()
        computed=evaluate(copy)
    db.close();return [f'decision_mismatch:{k}' for k in old.keys()|computed.keys() if old.get(k)!=computed.get(k)]
