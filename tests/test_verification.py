import ast,json,os,subprocess,sys,time
from pathlib import Path
from retaincase.ingest import initialize,load
from retaincase.rules import evaluate,action,recompute_frozen,verify_decisions
from retaincase.report import verify,verify_run,write_verification_report
from retaincase.store import connect

FIX=Path(__file__).resolve().parents[1]/'fixtures'

def setup(tmp):
    db=tmp/'x.db';initialize(db,FIX/'config.json');load(db,FIX/'events.jsonl');return db

def write_event(path,event):
    path.write_text(json.dumps(event,ensure_ascii=False),encoding='utf-8')

def v2_config(tmp,**overrides):
    cfg=json.loads((FIX/'config.json').read_text(encoding='utf-8'))
    cfg['rule_version']='v2';cfg.update(overrides)
    p=tmp/'v2.json';p.write_text(json.dumps(cfg,ensure_ascii=False),encoding='utf-8');return p

def build_counterexample(tmp):
    """r1 under v1/original events says D 可销毁; a late hold plus v2 follow."""
    db=setup(tmp);evaluate(db)
    con=connect(db);r1=con.execute('SELECT max(id) FROM run').fetchone()[0];con.close()
    hold=tmp/'hold.jsonl'
    write_event(hold,{'event_key':'late-hold','subject':'D','kind':'hold_start',
                      'hold_id':'court-late','at':'2026-03-01'})
    load(db,hold)
    action('recheck',db,out=v2_config(tmp))
    return db,r1

def test_old_policy_recomputes_historical_run_in_isolation(tmp_path):
    db,r1=build_counterexample(tmp_path)
    result=verify_run(db,r1)
    assert result['historical']['verdict']=='verified'
    assert result['current']['verdict']=='stale'
    # The frozen recompute never sees the supplemented event or the v2 bytes.
    frozen=recompute_frozen(db,r1,mode='frozen')
    assert frozen['config_hash']==connect(db).execute(
        'SELECT config_hash FROM run_input WHERE run_id=?',(r1,)).fetchone()[0]
    assert 4 not in {i for ids in frozen['membership'].values() for i in ids}
    assert frozen['decision']['D']=='可销毁'
    current=recompute_frozen(db,r1,mode='current')
    assert current['decision']['D']=='冻结'
    # Frozen recomputation runs on an isolated copy: source DB keeps both runs.
    assert connect(db).execute('SELECT count(*) FROM run').fetchone()[0]==2

def test_late_hold_current_contract_stale_not_historical_error(tmp_path):
    db,r1=build_counterexample(tmp_path)
    result=verify_run(db,r1)
    block=result['current']
    assert block['verdict']=='stale'
    assert set(block['reasons'])=={'events_supplemented','policy_revised','recomputed_drift'}
    assert [e['event_key'] for e in block['new_events']]==['late-hold']
    mismatch=next(m for m in block['mismatches'] if m['subject']=='D')
    assert (mismatch['stored'],mismatch['recomputed'])==('可销毁','冻结')
    assert mismatch['policy_digest']
    assert any(line['event_key']=='late-hold' for line in mismatch['raw_lines'])
    # Historical authenticity is untouched and the new hold is never backfilled
    # into the old run as its original error.
    assert result['historical']['mismatches']==[]
    assert connect(db).execute(
        'SELECT count(*) FROM run_input_event WHERE run_id=? AND event_id=(SELECT id FROM raw_event WHERE event_key=?)',
        (r1,'late-hold')).fetchone()[0]==0

def test_tampered_decision_row_distorts_both_contracts(tmp_path):
    db,r1=build_counterexample(tmp_path)
    con=connect(db)
    con.execute("UPDATE decision SET status='可销毁' WHERE run_id=? AND subject='B'",(r1,))
    con.commit();con.close()
    result=verify_run(db,r1)
    assert result['historical']['verdict']=='history_distorted'
    assert result['current']['verdict']=='history_distorted'
    mismatch=next(m for m in result['historical']['mismatches'] if m['subject']=='B')
    assert mismatch['field']=='decision.status'
    assert (mismatch['stored'],mismatch['recomputed'])==('可销毁','冻结')
    # Raw lines and the dependency propagation path (B depends_on A via d1).
    keys={line['event_key'] for line in mismatch['raw_lines']}
    assert {'h1','d1'}<=keys
    steps=[step for path in mismatch['dependency_paths'] for step in path]
    assert any(s['child']=='B' and s['parent']=='A' and s['event_key']=='d1' for s in steps)

def test_tampered_evidence_row_distorts_both_contracts(tmp_path):
    db=setup(tmp_path);evaluate(db)
    r1=connect(db).execute('SELECT max(id) FROM run').fetchone()[0]
    con=connect(db)
    con.execute("DELETE FROM evidence WHERE run_id=? AND subject='B' AND event_id IS NOT NULL",(r1,))
    con.commit();con.close()
    result=verify_run(db,r1)
    assert result['historical']['verdict']=='history_distorted'
    assert result['current']['verdict']=='history_distorted'
    assert 'stored_row_tampered' in result['historical']['reasons']
    mismatch=next(m for m in result['historical']['mismatches'] if m['subject']=='B')
    assert mismatch['field']=='evidence.events'
    assert mismatch['stored']==[] and set(mismatch['recomputed'])=={1,2}
    assert verify(db)  # generic byte-level verification also flags the row

def test_missing_frozen_evidence_is_unverifiable_not_recomputed_from_now(tmp_path):
    db=setup(tmp_path);evaluate(db)
    r1=connect(db).execute('SELECT max(id) FROM run').fetchone()[0]
    con=connect(db)
    con.execute('DELETE FROM run_input_event');con.execute('DELETE FROM run_input')
    con.commit();con.close()
    # Present state changes after the freeze evidence was lost; it must not be
    # used to manufacture a historical verdict.
    late=tmp_path/'late.jsonl'
    write_event(late,{'event_key':'late-hold','subject':'D','kind':'hold_start',
                      'hold_id':'court-late','at':'2026-03-01'})
    load(db,late)
    result=verify_run(db,r1)
    assert result['historical']['verdict']=='unverifiable'
    assert result['historical']['reasons']==['no_frozen_input']
    assert result['current']['verdict']=='unverifiable'
    assert 'no_frozen_input' in result['current']['reasons']
    # Decision rows are never touched by verification.
    assert connect(db).execute(
        "SELECT status FROM decision WHERE run_id=? AND subject='D'",(r1,)).fetchone()[0]=='可销毁'

def test_repeated_verification_is_stable_and_append_only(tmp_path):
    db,r1=build_counterexample(tmp_path)
    first=verify_run(db,r1)
    second=verify_run(db,r1)
    assert (first['historical']['verdict'],first['current']['verdict'])==(
        second['historical']['verdict'],second['current']['verdict'])
    assert first['historical']['mismatches']==second['historical']['mismatches']
    con=connect(db)
    rows=con.execute('SELECT run_id,contract,verdict FROM run_verification ORDER BY id').fetchall()
    assert len(rows)==4
    assert {r['contract'] for r in rows}=={'historical','current'}
    # Verification never overwrites run inputs nor creates runs/plans/executions.
    assert con.execute('SELECT count(*) FROM run').fetchone()[0]==2
    assert con.execute('SELECT count(*) FROM run_input').fetchone()[0]==2
    assert con.execute('SELECT count(*) FROM plan').fetchone()[0]==0
    assert con.execute('SELECT count(*) FROM execution').fetchone()[0]==0
    con.close()

def test_verification_never_authorizes_destruction(tmp_path):
    db,r1=build_counterexample(tmp_path)
    verify_run(db,r1)
    plan=tmp_path/'plan.json'
    action('plan',db,out=plan)
    # The stale run's 可销毁 verdict is historical record only: plans bind to the
    # latest run, whose D is 冻结, so D is absent from the destruction plan.
    assert [x['subject'] for x in json.loads(plan.read_text(encoding='utf-8'))]==[]
    assert connect(db).execute('SELECT count(*) FROM execution').fetchone()[0]==0
    report=write_verification_report(verify_run(db,r1),tmp_path/'v.json')
    assert 'verification_is_not_destruction_authorization' in report.read_text(encoding='utf-8')
    data=json.loads((tmp_path/'v.json').read_text(encoding='utf-8'))
    assert data['authorization_notice'].startswith('verification_is_not_destruction_authorization')

def test_verdict_is_timezone_invariant(tmp_path,monkeypatch):
    db=setup(tmp_path)
    con=connect(db)
    cfg=json.loads(con.execute('SELECT config_raw FROM batch').fetchone()[0])
    cfg['as_of']='2026-06-30T02:00:00Z';cfg['policy']['active']['days']=1
    import hashlib
    raw=json.dumps(cfg).encode()
    con.execute('UPDATE batch SET config_raw=?,config_hash=?',(raw,hashlib.sha256(raw).hexdigest()))
    con.commit();con.close()
    off=tmp_path/'offset.jsonl'
    off.write_text(json.dumps({'event_key':'u-offset','subject':'C','kind':'use',
                               'at':'2026-06-29T23:30:00-02:00'}),encoding='utf-8')
    assert load(db,off)==1
    evaluate(db)
    r1=connect(db).execute('SELECT max(id) FROM run').fetchone()[0]
    verdicts=[]
    for tz in ('UTC','Asia/Tokyo','America/Los_Angeles'):
        monkeypatch.setenv('TZ',tz)
        if hasattr(time,'tzset'):time.tzset()
        # Fresh isolated verification each time: persisted verdicts must not be
        # compared against each other, and verification rows are append-only.
        result=verify_run(db,r1,persist=False)
        verdicts.append((result['historical']['verdict'],result['current']['verdict']))
    assert verdicts==[('verified','verified')]*3
    # The offset event is 2026-06-30 01:30 UTC -> within the 1-day window -> 冻结.
    assert recompute_frozen(db,r1,mode='frozen')['decision']['C']=='冻结'

def test_events_only_supplementation_marks_stale_without_policy_revision(tmp_path):
    db=setup(tmp_path);evaluate(db)
    r1=connect(db).execute('SELECT max(id) FROM run').fetchone()[0]
    late=tmp_path/'late.jsonl'
    write_event(late,{'event_key':'late-hold','subject':'D','kind':'hold_start',
                      'hold_id':'court-late','at':'2026-03-01'})
    load(db,late)
    result=verify_run(db,r1)
    assert result['historical']['verdict']=='verified'
    assert result['current']['verdict']=='stale'
    assert result['current']['reasons']==['events_supplemented','recomputed_drift']
    assert result['current']['current_policy_digest']==result['historical']['policy_digest']

def test_watermark_excludes_events_ingested_after_run(tmp_path):
    db,r1=build_counterexample(tmp_path)
    frozen=recompute_frozen(db,r1,mode='frozen')
    con=connect(db)
    wm=con.execute('SELECT event_watermark FROM run_input WHERE run_id=?',(r1,)).fetchone()[0]
    late_id=con.execute("SELECT id FROM raw_event WHERE event_key='late-hold'").fetchone()[0]
    con.close()
    assert late_id>wm
    assert frozen['event_watermark']==wm
    assert all(late_id not in ids for ids in frozen['membership'].values())

def test_freeze_digest_tampering_is_distortion_not_unverifiable(tmp_path):
    db=setup(tmp_path);evaluate(db)
    r1=connect(db).execute('SELECT max(id) FROM run').fetchone()[0]
    con=connect(db)
    con.execute("UPDATE run_input SET input_digest=? WHERE run_id=?",('0'*64,r1))
    con.commit();con.close()
    result=verify_run(db,r1)
    assert result['historical']['verdict']=='history_distorted'
    assert 'freeze_membership_tampered' in result['historical']['reasons']

def test_frozen_policy_byte_tampering_is_distortion(tmp_path):
    db=setup(tmp_path);evaluate(db)
    r1=connect(db).execute('SELECT max(id) FROM run').fetchone()[0]
    con=connect(db)
    row=con.execute('SELECT config_raw FROM run_input WHERE run_id=?',(r1,)).fetchone()
    cfg=json.loads(row['config_raw']);cfg['policy']['ordinary']['days']=365
    con.execute('UPDATE run_input SET config_raw=? WHERE run_id=?',(json.dumps(cfg).encode(),r1))
    con.commit();con.close()
    result=verify_run(db,r1)
    assert result['historical']['verdict']=='history_distorted'
    assert 'freeze_policy_tampered' in result['historical']['reasons']

def test_membership_table_tampering_is_distortion(tmp_path):
    db=setup(tmp_path);evaluate(db)
    r1=connect(db).execute('SELECT max(id) FROM run').fetchone()[0]
    con=connect(db)
    con.execute('DELETE FROM run_input_event WHERE run_id=? AND subject=?',(r1,'B'))
    con.commit();con.close()
    result=verify_run(db,r1)
    assert result['historical']['verdict']=='history_distorted'
    assert 'freeze_membership_tampered' in result['historical']['reasons']

def test_verify_decisions_uses_frozen_inputs_of_latest_run(tmp_path):
    db=setup(tmp_path);evaluate(db)
    assert verify_decisions(db)==[]
    # A supplemented event must not make the latest frozen run look wrong.
    late=tmp_path/'late.jsonl'
    write_event(late,{'event_key':'late-hold','subject':'D','kind':'hold_start',
                      'hold_id':'court-late','at':'2026-03-01'})
    load(db,late)
    assert verify_decisions(db)==[]
    con=connect(db)
    con.execute("UPDATE decision SET status='可销毁' WHERE run_id=(SELECT max(id) FROM run) AND subject='B'")
    con.commit();con.close()
    assert 'decision_mismatch:B' in verify_decisions(db)

def test_legacy_run_without_freeze_reported_unverifiable_by_verify_decisions(tmp_path):
    db=setup(tmp_path);evaluate(db)
    con=connect(db);con.execute('DELETE FROM run_input_event');con.execute('DELETE FROM run_input');con.commit();con.close()
    assert verify_decisions(db)==['unverifiable_run:1:no_frozen_input']

def test_verify_decisions_survives_byte_tampered_event(tmp_path):
    db=setup(tmp_path);evaluate(db)
    con=connect(db)
    con.execute("UPDATE raw_event SET payload='{}' WHERE id=(SELECT min(id) FROM raw_event)")
    con.commit();con.close()
    problems=verify_decisions(db)
    assert problems==['run_input_chain_tampered:1']

def test_cli_verify_run_outputs_two_contracts(tmp_path):
    db,r1=build_counterexample(tmp_path)
    out=tmp_path/'verify.json'
    env={'PATH':os.environ.get('PATH',''),'PYTHONPATH':str(Path(__file__).resolve().parents[1])}
    proc=subprocess.run([sys.executable,'-m','retaincase','verify-run','--db',str(db),
                         '--run',str(r1),'--out',str(out)],capture_output=True,text=True,env=env)
    assert proc.returncode==0,proc.stderr
    printed=ast.literal_eval(proc.stdout.strip().splitlines()[-1])
    assert printed=={'run_id':r1,'historical':'verified','current':'stale'}
    data=json.loads(out.read_text(encoding='utf-8'))
    assert data['run_id']==r1 and data['historical']['verdict']=='verified'
    md=out.with_suffix('.md').read_text(encoding='utf-8')
    assert '历史真实性合同' in md and '现时可用性合同' in md and '现时过期' in md

def test_report_mismatch_lists_raw_lines_policy_and_paths(tmp_path):
    db,r1=build_counterexample(tmp_path)
    con=connect(db)
    con.execute("UPDATE decision SET status='可销毁' WHERE run_id=? AND subject='B'",(r1,))
    con.commit();con.close()
    report=write_verification_report(verify_run(db,r1),tmp_path/'v.json')
    md=report.with_suffix('.md').read_text(encoding='utf-8')
    assert '历史失真' in md
    assert '政策摘要=' in md and '原始行' in md and '依赖传递路径' in md
    data=json.loads(report.read_text(encoding='utf-8'))
    mismatch=next(m for m in data['historical']['mismatches'] if m['subject']=='B')
    assert all('raw_line' in line for line in mismatch['raw_lines'])
    assert mismatch['policy_digest']==data['historical']['policy_digest']

def test_rewritten_event_bytes_distort_both_contracts(tmp_path):
    db=setup(tmp_path);evaluate(db)
    r1=connect(db).execute('SELECT max(id) FROM run').fetchone()[0]
    con=connect(db)
    con.execute("UPDATE raw_event SET payload='{}' WHERE id=(SELECT min(id) FROM raw_event)")
    con.commit();con.close()
    result=verify_run(db,r1)
    assert result['historical']['verdict']=='history_distorted'
    assert result['current']['verdict']=='history_distorted'
    assert 'source_chain_tampered' in result['historical']['reasons']
    assert any(p.startswith('event:') for p in result['historical']['chain_problems'])

def test_store_keeps_version_relationship_without_overwriting(tmp_path):
    db,r1=build_counterexample(tmp_path)
    con=connect(db)
    rows=con.execute('SELECT run_id,config_hash,event_watermark FROM run_input ORDER BY run_id').fetchall()
    assert [r['run_id'] for r in rows]==[1,2]
    assert rows[0]['config_hash']!=rows[1]['config_hash']
    assert rows[0]['event_watermark']<rows[1]['event_watermark']
    # Old run's decision rows survive the policy revision and the verifications.
    assert con.execute("SELECT status FROM decision WHERE run_id=1 AND subject='D'").fetchone()[0]=='可销毁'
    assert con.execute("SELECT status FROM decision WHERE run_id=2 AND subject='D'").fetchone()[0]=='冻结'
    con.close()
