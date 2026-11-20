import json
from pathlib import Path

import pytest

from retaincase.ingest import initialize, load
from retaincase.rules import evaluate
from retaincase.requests import triage, fulfill
from retaincase.handoff import prepare, acknowledge
from retaincase.recall import open_case, submit
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
    assert triage(other,'REQ-Y',['D'],'2099-01-01T00:00:00Z')['items'][0]['obligation']=='remote_erase'

def test_recall_partial_receipts_then_remote_fulfillment(tmp_path):
    fixture=json.loads((FIX/'recall-cases.json').read_text(encoding='utf-8'))
    config=json.loads((FIX/'config.json').read_text(encoding='utf-8'))
    config['subjects']['E']=fixture['additional_subject']
    config_path=tmp_path/'config.json';config_path.write_text(json.dumps(config),encoding='utf-8')
    db=tmp_path/'ledger.db';initialize(db,config_path);load(db,FIX/'events.jsonl');evaluate(db)
    prepare(db,'T','receiver-A',['D','E'],'2099-01-01T00:00:00Z')
    assert acknowledge(db,'T','receiver-A',fixture['ack_hashes'],'2030-01-01T00:00:00Z')['state']=='accepted'
    request=triage(db,'REQ',['D','E'],'2099-01-01T00:00:00Z')
    assert {x['obligation'] for x in request['items']}=={'remote_erase'}
    assert fulfill(db,'REQ')['missing_remote_receipt']==['D','E']
    assert open_case(db,'RC','REQ','T')['state']=='pending'
    partial=submit(db,'RC','receiver-A',fixture['first_batch'])
    assert partial['state']=='partial'
    assert {x['subject']:x['state'] for x in partial['items']}=={'D':'confirmed','E':'disputed'}
    assert fulfill(db,'REQ')['missing_remote_receipt']==['D','E']
    assert submit(db,'RC','receiver-A',fixture['retry'])['state']=='completed'
    assert fulfill(db,'REQ')['state']=='fulfilled'

def test_recall_rejects_forged_receipt_and_conflicting_key(tmp_path):
    fixture=json.loads((FIX/'recall-cases.json').read_text(encoding='utf-8'))
    db=ready(tmp_path)
    prepare(db,'T','receiver-A',['D'],'2099-01-01T00:00:00Z')
    acknowledge(db,'T','receiver-A',{'D':fixture['ack_hashes']['D']},'2030-01-01T00:00:00Z')
    triage(db,'REQ',['D'],'2099-01-01T00:00:00Z');open_case(db,'RC','REQ','T')
    forged={**fixture['first_batch'][0],'certificate':'forged'}
    assert submit(db,'RC','receiver-A',[forged])['state']=='disputed'
    with pytest.raises(ValueError,match='receipt_identity_conflict'):
        submit(db,'RC','receiver-A',[fixture['first_batch'][0]])
    with pytest.raises(ValueError,match='recall_recipient_mismatch'):
        submit(db,'RC','receiver-B',[fixture['retry'][0]])
