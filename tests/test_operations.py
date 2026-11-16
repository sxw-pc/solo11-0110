import json
from pathlib import Path

import pytest

from retaincase.ingest import initialize, load
from retaincase.rules import evaluate
from retaincase.requests import triage, fulfill
from retaincase.handoff import prepare, acknowledge
from retaincase.store import connect

FIX = Path(__file__).resolve().parent.parent / 'fixtures'

def ready(tmp_path):
    tmp_path.mkdir(parents=True,exist_ok=True)
    db=tmp_path/'ledger.db'
    initialize(db,FIX/'config.json');load(db,FIX/'events.jsonl');evaluate(db)
    return db

def test_erasure_request_has_distinct_per_object_obligations(tmp_path):
    db=ready(tmp_path)
    case=json.loads((FIX/'operations.json').read_text(encoding='utf-8'))['partial_request']
    result=triage(db,case['id'],case['subjects'],case['due'])
    assert result['state'] in {'partial','uncertain'}
    assert len({x['obligation'] for x in result['items']})==2
    assert triage(db,'REQ-1',['A','D'],'2099-01-01T00:00:00Z')==result
    with pytest.raises(ValueError,match='request_identity_conflict'):
        triage(db,'REQ-1',['D'],'2099-01-01T00:00:00Z')

def test_fulfillment_requires_proven_execution_not_absence(tmp_path):
    db=ready(tmp_path)
    triage(db,'REQ-2',['D'],'2099-01-01T00:00:00Z')
    assert fulfill(db,'REQ-2')['missing_execution']==['D']
    con=connect(db)
    run=con.execute('SELECT max(id) FROM run').fetchone()[0]
    with con:
        con.execute("INSERT INTO execution(run_id,subject,action,before_hash,after_state) VALUES (?,?,?,?,?)",
                    (run,'D','destroy','fixture-hash','absent'))
    assert fulfill(db,'REQ-2')['state']=='fulfilled'
    evaluate(db)
    with pytest.raises(ValueError,match='request_decision_stale'):
        fulfill(db,'REQ-2')

def test_custody_transfer_freezes_run_and_requires_exact_ack(tmp_path):
    db=ready(tmp_path)
    expected=json.loads((FIX/'config.json').read_text(encoding='utf-8'))['subjects']['D']['sha256']
    prepared=prepare(db,'T-1','receiver-A',['D'],'2099-01-01T00:00:00Z')
    assert prepared['state']=='prepared'
    assert acknowledge(db,'T-1','receiver-A',{'D':expected},'2030-01-01T00:00:00Z')['state']=='accepted'
    assert acknowledge(db,'T-1','receiver-A',{'D':expected},'2030-01-01T00:00:00Z')['state']=='accepted'

def test_custody_dispute_and_stale_decision(tmp_path):
    db=ready(tmp_path)
    prepare(db,'T-2','receiver-A',['D'],'2099-01-01T00:00:00Z')
    assert acknowledge(db,'T-2','receiver-B',{'D':'wrong'},'2030-01-01T00:00:00Z')['state']=='disputed'
    prepare(db,'T-3','receiver-A',['D'],'2099-01-01T00:00:00Z')
    evaluate(db)
    expected=json.loads((FIX/'config.json').read_text(encoding='utf-8'))['subjects']['D']['sha256']
    assert acknowledge(db,'T-3','receiver-A',{'D':expected},'2030-01-01T00:00:00Z')['state']=='disputed'

def test_request_and_custody_have_cross_object_constraints(tmp_path):
    db=ready(tmp_path)
    triage(db,'REQ-X',['D'],'2099-01-01T00:00:00Z')
    with pytest.raises(ValueError,match='pending_erasure_request'):
        prepare(db,'T-X','receiver-A',['D'],'2099-01-01T00:00:00Z')
    other=ready(tmp_path/'other')
    expected=json.loads((FIX/'config.json').read_text(encoding='utf-8'))['subjects']['D']['sha256']
    prepare(other,'T-Y','receiver-A',['D'],'2099-01-01T00:00:00Z')
    acknowledge(other,'T-Y','receiver-A',{'D':expected},'2030-01-01T00:00:00Z')
    assert triage(other,'REQ-Y',['D'],'2099-01-01T00:00:00Z')['items'][0]['obligation']=='investigate'
