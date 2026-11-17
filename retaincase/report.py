import json
from pathlib import Path
from .store import connect
def export(db_path,out):
    db=connect(db_path);out=Path(out);out.parent.mkdir(parents=True,exist_ok=True)
    run=db.execute('SELECT * FROM run ORDER BY id DESC LIMIT 1').fetchone()
    if not run:raise ValueError('no_run')
    rid=run['id'];data={'run':dict(run),'sources':[{'id':x['id'],'name':x['name'],'digest':x['digest']} for x in db.execute('SELECT * FROM source_file ORDER BY id')],
      'decisions':[dict(x) for x in db.execute('SELECT * FROM decision WHERE run_id=? ORDER BY subject',(rid,))],
      'issues':[dict(x) for x in db.execute('SELECT * FROM issue WHERE run_id=? OR run_id IS NULL ORDER BY id',(rid,))],
      'evidence':[dict(x) for x in db.execute('SELECT * FROM evidence WHERE run_id=? ORDER BY id',(rid,))]}
    data['executions']=[dict(x) for x in db.execute('SELECT * FROM execution ORDER BY id')]
    data['forecasts']=[{'forecast_run':dict(fr),
                        'items':[dict(x) for x in db.execute('SELECT * FROM forecast WHERE forecast_run_id=? ORDER BY subject,contract',(fr['id'],))]}
                       for fr in db.execute('SELECT * FROM forecast_run ORDER BY id')]
    out.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    lines=['# 离线判定报告','',f'运行 {rid}：{run["status"]}','']
    lines+=[f'- {x["subject"]}: {x["status"]}，{x["detail"]}' for x in data['decisions']]
    if data['forecasts']:
        lines+=['','## 复核时点预报','','仅供保管员安排证据收集与人工复核，不构成可销毁授权。']
        for block in data['forecasts']:
            fr=block['forecast_run'];watermark=json.loads(fr['watermark'])
            lines+=['',f'预报 {fr["id"]}（锚定运行 {fr["run_id"]}，规则 {fr["rule_version"]}，as_of {fr["as_of"]}，事件水位 {watermark["count"]} 条）']
            for item in block['items']:
                detail=json.loads(item['detail']);premises='；'.join(item['premises'] and json.loads(item['premises']) or []) or '无'
                date=item['review_date'] or '—'
                chain='、'.join(f"{e['child']}→{e['parent']}" for e in detail['dependency_chain']) or '无'
                lines.append(f'- {item["subject"]} [{detail["contract_label"]}]: {item["level"]}，复核日 {date}，前提：{premises}，依赖链：{chain}')
    md=out.with_suffix('.md');md.write_text('\n'.join(lines)+'\n',encoding='utf-8')
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
        if db.execute('SELECT 1 FROM raw_event WHERE subject=?',(d['subject'],)).fetchone() and not db.execute(
            'SELECT 1 FROM evidence WHERE run_id=? AND subject=? AND event_id IS NOT NULL',(d['run_id'],d['subject'])).fetchone():
            problems.append(f'decision_source:{d["id"]}')
    db.close();return problems
