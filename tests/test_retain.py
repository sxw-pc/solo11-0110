import json,hashlib
from pathlib import Path
import pytest
from retaincase.ingest import initialize,load
from retaincase.rules import evaluate,action,verify_decisions
from retaincase.report import export,verify
from retaincase.store import connect
FIX=Path(__file__).resolve().parents[1]/'fixtures'
def setup(tmp):
    db=tmp/'x.db';initialize(db,FIX/'config.json');load(db,FIX/'events.jsonl');return db
def test_demo_decisions(tmp_path):
    assert evaluate(setup(tmp_path))=={'A':'冻结','B':'冻结','C':'冻结','D':'可销毁'}
def test_import_idempotent_and_conflict(tmp_path):
    db=setup(tmp_path);assert load(db,FIX/'events.jsonl')==0
    p=tmp_path/'conflict.jsonl';p.write_text(json.dumps({'event_key':'h1','subject':'B','kind':'hold_end','at':'2026-05-01'}))
    assert load(db,p)==0
    assert connect(db).execute("SELECT count(*) FROM issue WHERE code='identity_conflict'").fetchone()[0]==1
def test_missing_start_unknown(tmp_path):
    db=setup(tmp_path);cfg=json.loads((FIX/'config.json').read_text());cfg['subjects']['C']['created']=None
    # Last-use start still exists; remove the event instead.
    con=connect(db);con.execute("DELETE FROM raw_event WHERE subject='C'");con.commit();con.close()
    assert evaluate(db)['C']=='证据不足'
def test_hold_release(tmp_path):
    db=setup(tmp_path);p=tmp_path/'release.jsonl';p.write_text(json.dumps({'event_key':'end','subject':'B','kind':'hold_end','hold_id':'court-1','at':'2026-05-01'}))
    load(db,p);result=evaluate(db);assert result['B']=='可销毁' and result['A']=='可销毁'
def test_dependency_cycle(tmp_path):
    db=setup(tmp_path);p=tmp_path/'cycle.jsonl';p.write_text(json.dumps({'event_key':'cycle','subject':'A','kind':'depends_on','parent':'B','at':'2026-02-03'}))
    load(db,p);assert evaluate(db)['A']=='证据不足'
def test_plan_and_execute(tmp_path):
    db=setup(tmp_path);evaluate(db);plan=tmp_path/'plan.json';action('plan',db,out=plan)
    assert [x['subject'] for x in json.loads(plan.read_text())]==['D']
    root=tmp_path/'sandbox';root.mkdir();(root/'D.bin').write_bytes(b'demo')
    assert action('execute',db,sandbox=root,out=plan)==['D'];assert not (root/'D.bin').exists()
def test_plan_rejects_path_escape(tmp_path):
    db=setup(tmp_path);con=connect(db);cfg=json.loads(con.execute('SELECT config_raw FROM batch').fetchone()[0]);cfg['subjects']['D']['path']='../escape'
    con.execute('UPDATE batch SET config_raw=?',(json.dumps(cfg).encode(),));con.commit();con.close();evaluate(db)
    with pytest.raises(ValueError,match='unsafe_plan'):action('plan',db,out=tmp_path/'plan.json')
def test_evidence_report_and_recheck(tmp_path):
    db=setup(tmp_path);evaluate(db);out=export(db,tmp_path/'report.json');assert out.with_suffix('.md').exists();assert verify(db)==[]
    assert evaluate(db)['D']=='可销毁'
    con=connect(db);assert con.execute('SELECT count(*) FROM run').fetchone()[0]==2
def test_policy_revision_preserves_history(tmp_path):
    db=setup(tmp_path);evaluate(db);cfg=json.loads((FIX/'config.json').read_text());cfg['rule_version']='v2';cfg['policy']['ordinary']['days']=365
    p=tmp_path/'v2.json';p.write_text(json.dumps(cfg))
    assert action('recheck',db,out=p)['D']=='冻结'
    con=connect(db);assert con.execute('SELECT count(*) FROM run').fetchone()[0]==2
    assert con.execute('SELECT count(*) FROM rule_version').fetchone()[0]==2
def test_execute_detects_tamper_and_idempotence(tmp_path):
    db=setup(tmp_path);evaluate(db);plan=tmp_path/'plan.json';action('plan',db,out=plan)
    root=tmp_path/'sandbox';root.mkdir();target=root/'D.bin';target.write_bytes(b'tampered')
    with pytest.raises(ValueError,match='hash_changed'):action('execute',db,sandbox=root,out=plan)
    target.write_bytes(b'demo');assert action('execute',db,sandbox=root,out=plan)==['D']
    assert action('execute',db,sandbox=root,out=plan)==[]
    assert connect(db).execute('SELECT count(*) FROM execution').fetchone()[0]==1
def test_batch_config_conflict(tmp_path):
    db=setup(tmp_path);cfg=json.loads((FIX/'config.json').read_text());cfg['as_of']='2027-01-01';p=tmp_path/'other.json';p.write_text(json.dumps(cfg))
    with pytest.raises(ValueError,match='batch_config_conflict'):initialize(db,p)
def test_overlapping_holds_require_all_release(tmp_path):
    db=setup(tmp_path);p=tmp_path/'more.jsonl';p.write_text('\n'.join(json.dumps(x) for x in [
      {'event_key':'h2','subject':'B','kind':'hold_start','hold_id':'court-2','at':'2026-03-01'},
      {'event_key':'e1','subject':'B','kind':'hold_end','hold_id':'court-1','at':'2026-04-01'}]))
    load(db,p);assert evaluate(db)['B']=='冻结'
def test_expiry_boundary(tmp_path):
    db=setup(tmp_path);con=connect(db);cfg=json.loads(con.execute('SELECT config_raw FROM batch').fetchone()[0]);cfg['as_of']='2026-01-31';con.execute('UPDATE batch SET config_raw=?',(json.dumps(cfg).encode(),));con.commit();con.close()
    assert evaluate(db)['D']=='可销毁'
def test_report_has_source_hash(tmp_path):
    db=setup(tmp_path);evaluate(db);p=export(db,tmp_path/'r.json');data=json.loads(p.read_text(encoding='utf-8'));assert data['sources'][0]['digest'] and data['evidence']
def test_scoped_hold_matches_tag(tmp_path):
    db=setup(tmp_path);p=tmp_path/'scope.jsonl';p.write_text(json.dumps({'event_key':'scope-1','subject':'B','kind':'hold_start','hold_id':'court-scope','scope_tag':'regulated','at':'2026-03-01'}));load(db,p)
    assert evaluate(db)['D']=='冻结'
def test_independent_recheck_detects_tampered_decision(tmp_path):
    db=setup(tmp_path);evaluate(db);assert verify_decisions(db)==[]
    con=connect(db);con.execute("UPDATE decision SET status='可销毁' WHERE subject='B'");con.commit();con.close()
    assert 'decision_mismatch:B' in verify_decisions(db)
