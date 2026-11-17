import json
import subprocess
import sys
from pathlib import Path

import pytest

from retaincase.ingest import initialize, load
from retaincase.rules import evaluate, action
from retaincase.forecast import forecast
from retaincase.report import export, verify
from retaincase.store import connect

FIX = Path(__file__).resolve().parents[1] / 'fixtures'
ROOT = Path(__file__).resolve().parents[1]


def make_db(tmp_path, cfg, events=()):
    config_path = tmp_path / 'cfg.json'
    config_path.write_text(json.dumps(cfg), encoding='utf-8')
    db = tmp_path / 'forecast.db'
    initialize(db, config_path)
    if events:
        feed(tmp_path, db, events)
    return db


def feed(tmp_path, db, events, name='events.jsonl'):
    p = tmp_path / name
    p.write_text('\n'.join(json.dumps(e) for e in events), encoding='utf-8')
    return load(db, p)


def cfg_for(subjects, as_of='2026-06-10', start='last_use', days=30):
    return {'batch_id': 'forecast-case', 'rule_version': 'v1', 'as_of': as_of,
            'policy': {'active': {'start': start, 'days': days},
                       'ordinary': {'start': 'created', 'days': days}},
            'subjects': subjects}


def demo_db(tmp_path):
    db = tmp_path / 'x.db'
    initialize(db, FIX / 'config.json')
    load(db, FIX / 'events.jsonl')
    return db


def test_demo_fixture_levels_and_dates(tmp_path):
    db = demo_db(tmp_path)
    evaluate(db)
    r = forecast(db)['subjects']
    # D：无保全无依赖，期限已过，两合同都给出保证日期
    assert r['D']['audit']['level'] == '保证到期' and r['D']['audit']['review_date'] == '2026-01-31'
    assert r['D']['operational']['level'] == '保证到期'
    # B：保全未解除，审计合同无法预报，运营合同给条件日期并列出解除前提
    assert r['B']['audit']['level'] == '无法预报'
    assert r['B']['operational']['level'] == '有条件'
    assert any('court-1' in p for p in r['B']['operational']['premises'])
    # A：子对象 B 无法预报，审计合同被依赖阻断；运营合同继承前提
    assert r['A']['audit']['level'] == '无法预报'
    assert r['A']['operational']['level'] == '有条件'
    assert any('court-1' in p for p in r['A']['operational']['premises'])
    # C：last_use 有一次历史 use，审计合同保证 2026-05-20+30 天
    assert r['C']['audit']['level'] == '保证到期' and r['C']['audit']['review_date'] == '2026-06-19'
    assert r['C']['operational']['level'] == '有条件'
    assert any('use' in p for p in r['C']['operational']['premises'])


def test_future_use_splits_contracts_and_keeps_decision(tmp_path):
    """反例：last_use 起点，6 月 1 日已用、6 月 20 日未来已用，期限 30 天。

    审计保证合同不得把 7 月 1 日写成保证释放日期；运营排程合同可给 7 月 20 日
    条件复核日期并列出“之后无新 use”前提；两合同排程决定不同，当前销毁资格不变。
    """
    cfg = cfg_for({'C': {'created': '2026-01-01', 'category': 'active', 'path': 'C.bin'}})
    db = make_db(tmp_path, cfg, [
        {'event_key': 'u1', 'subject': 'C', 'kind': 'use', 'at': '2026-06-01'},
        {'event_key': 'u2', 'subject': 'C', 'kind': 'use', 'at': '2026-06-20'}])
    before = evaluate(db)
    runs_before = connect(db).execute('SELECT count(*) FROM run').fetchone()[0]
    result = forecast(db)
    ops = result['subjects']['C']['operational']
    aud = result['subjects']['C']['audit']
    assert ops['level'] == '有条件' and ops['review_date'] == '2026-07-20'
    assert any('之后无新 use' in p for p in ops['premises'])
    assert aud['level'] == '无法预报' and aud['review_date'] is None
    assert not (aud['level'] == '保证到期' and aud['review_date'] == '2026-07-01')
    assert ops['review_date'] != aud['review_date'] or ops['level'] != aud['level']
    # 预报不产生新 run、不改写裁决；当前销毁资格不变
    con = connect(db)
    assert con.execute('SELECT count(*) FROM run').fetchone()[0] == runs_before
    assert evaluate(db) == before == {'C': '冻结'}


def test_offset_event_forecast_uses_utc_day(tmp_path):
    """本地 6 月 20 日 00:30+08:00 是 UTC 6 月 19 日，预报按 6 月 19 日起算。"""
    cfg = cfg_for({'C': {'created': '2026-01-01', 'category': 'active', 'path': 'C.bin'}})
    db = make_db(tmp_path, cfg, [
        {'event_key': 'u1', 'subject': 'C', 'kind': 'use', 'at': '2026-06-01'},
        {'event_key': 'u2', 'subject': 'C', 'kind': 'use', 'at': '2026-06-20T00:30:00+08:00'}])
    ops = forecast(db)['subjects']['C']['operational']
    assert ops['review_date'] == '2026-07-19'  # UTC 06-19 + 30 天，而非本地 06-20 + 30 天
    days = {e['event_key']: e['utc_day'] for e in ops['basis']['start_events']}
    assert days['u2'] == '2026-06-19'


def test_unreleased_hold_blocks_guarantee_until_released(tmp_path):
    cfg = cfg_for({'B': {'created': '2026-01-01', 'category': 'ordinary', 'path': 'B.bin'}},
                  as_of='2026-06-01')
    db = make_db(tmp_path, cfg, [
        {'event_key': 'h1', 'subject': 'B', 'kind': 'hold_start', 'hold_id': 'court-1', 'at': '2026-02-01'}])
    r = forecast(db)['subjects']['B']
    # 期限早已届满，但未解除保全不得给出保证日期
    assert r['audit']['level'] == '无法预报' and r['audit']['review_date'] is None
    assert r['operational']['level'] == '有条件' and r['operational']['review_date'] == '2026-01-31'
    assert any('court-1' in p for p in r['operational']['premises'])
    # 解除保全（半开区间：解除当日即自由）后两合同都给出保证日期
    feed(tmp_path, db, [{'event_key': 'e1', 'subject': 'B', 'kind': 'hold_end',
                         'hold_id': 'court-1', 'at': '2026-05-01'}], name='rel.jsonl')
    r2 = forecast(db)['subjects']['B']
    assert r2['audit']['level'] == '保证到期' and r2['audit']['review_date'] == '2026-05-01'
    assert r2['operational']['level'] == '保证到期' and r2['operational']['review_date'] == '2026-05-01'


def test_terminated_start_never_guesses_from_created(tmp_path):
    cfg = cfg_for({'T': {'created': '2026-01-01', 'category': 'active', 'path': 'T.bin'}},
                  start='terminated')
    db = make_db(tmp_path, cfg)
    r = forecast(db)['subjects']['T']
    for contract in ('audit', 'operational'):
        assert r[contract]['level'] == '无法预报' and r[contract]['review_date'] is None
    assert any(b['code'] == 'no_start_evidence' for b in r['operational']['blocking'])
    # 补上 terminate 起点后，两合同按起点给出日期
    feed(tmp_path, db, [{'event_key': 't1', 'subject': 'T', 'kind': 'terminate', 'at': '2026-05-01'}],
         name='t.jsonl')
    r2 = forecast(db)['subjects']['T']
    assert r2['audit']['level'] == '保证到期' and r2['audit']['review_date'] == '2026-05-31'
    assert r2['operational']['review_date'] == '2026-05-31'
    assert any('terminate' in p for p in r2['operational']['premises'])


def test_dependency_multihop_constrains_sources(tmp_path):
    subjects = {'P': {'created': '2026-01-01', 'category': 'ordinary', 'path': 'P.bin'},
                'M': {'created': '2026-01-01', 'category': 'ordinary', 'path': 'M.bin'},
                'L': {'created': '2026-05-01', 'category': 'ordinary', 'path': 'L.bin'}}
    cfg = cfg_for(subjects, as_of='2026-06-01')
    db = make_db(tmp_path, cfg, [
        {'event_key': 'd1', 'subject': 'M', 'kind': 'depends_on', 'parent': 'P', 'at': '2026-01-05'},
        {'event_key': 'd2', 'subject': 'L', 'kind': 'depends_on', 'parent': 'M', 'at': '2026-01-06'}])
    r = forecast(db)['subjects']
    # 叶子 L 最晚才能释放，约束沿链传递到 M 和 P
    assert r['L']['audit']['review_date'] == '2026-05-31'
    assert r['M']['audit']['review_date'] == '2026-05-31'
    assert r['P']['audit']['review_date'] == '2026-05-31'
    chain = {(e['child'], e['parent']) for e in r['P']['audit']['dependency_chain']}
    assert chain == {('M', 'P'), ('L', 'M')}


def test_dependency_cycle_blocks_without_pseudo_dates(tmp_path):
    subjects = {'A': {'created': '2026-01-01', 'category': 'ordinary', 'path': 'A.bin'},
                'B': {'created': '2026-01-01', 'category': 'ordinary', 'path': 'B.bin'}}
    cfg = cfg_for(subjects, as_of='2026-06-01')
    db = make_db(tmp_path, cfg, [
        {'event_key': 'd1', 'subject': 'A', 'kind': 'depends_on', 'parent': 'B', 'at': '2026-01-05'},
        {'event_key': 'd2', 'subject': 'B', 'kind': 'depends_on', 'parent': 'A', 'at': '2026-01-06'}])
    r = forecast(db)['subjects']
    for subject in ('A', 'B'):
        for contract in ('audit', 'operational'):
            entry = r[subject][contract]
            assert entry['level'] == '无法预报' and entry['review_date'] is None
            assert any(b['code'] == 'dependency_cycle' for b in entry['blocking'])
    keys = {k for b in r['A']['operational']['blocking'] for k in b['event_keys']}
    assert {'d1', 'd2'} & keys


def test_missing_parent_lists_blocking_evidence(tmp_path):
    cfg = cfg_for({'X': {'created': '2026-01-01', 'category': 'ordinary', 'path': 'X.bin'}},
                  as_of='2026-06-01')
    db = make_db(tmp_path, cfg, [
        {'event_key': 'd9', 'subject': 'X', 'kind': 'depends_on', 'parent': 'ghost', 'at': '2026-01-05'}])
    r = forecast(db)['subjects']['X']
    for contract in ('audit', 'operational'):
        assert r[contract]['level'] == '无法预报' and r[contract]['review_date'] is None
        blocking = [b for b in r[contract]['blocking'] if b['code'] == 'missing_dependency']
        assert blocking and 'd9' in blocking[0]['event_keys']


def test_late_events_and_replay_never_rewrite(tmp_path):
    cfg = cfg_for({'C': {'created': '2026-01-01', 'category': 'active', 'path': 'C.bin'}})
    db = make_db(tmp_path, cfg, [
        {'event_key': 'u1', 'subject': 'C', 'kind': 'use', 'at': '2026-06-01'}])
    first = forecast(db)
    assert first['subjects']['C']['audit']['review_date'] == '2026-07-01'
    assert first['subjects']['C']['audit']['level'] == '保证到期'
    # 同输入重放：生成新预报行，内容相同，旧预报保留
    replay = forecast(db)
    assert replay['forecast_run'] != first['forecast_run']
    assert replay['subjects'] == first['subjects']
    # 迟到事件（过去日期的 use 晚到）只产生新预报
    feed(tmp_path, db, [{'event_key': 'u-late', 'subject': 'C', 'kind': 'use', 'at': '2026-06-05'}],
         name='late.jsonl')
    second = forecast(db)
    assert second['subjects']['C']['audit']['review_date'] == '2026-07-05'
    assert second['subjects']['C']['operational']['review_date'] == '2026-07-05'
    con = connect(db)
    assert con.execute('SELECT count(*) FROM forecast_run').fetchone()[0] == 3
    old = con.execute('SELECT level,review_date FROM forecast WHERE forecast_run_id=? AND subject=? AND contract=?',
                      (first['forecast_run'], 'C', 'audit')).fetchone()
    assert tuple(old) == ('保证到期', '2026-07-01')


def test_recheck_and_policy_change_regenerate_not_rewrite(tmp_path):
    cfg = cfg_for({'D': {'created': '2026-01-01', 'category': 'ordinary', 'path': 'D.bin'}},
                  as_of='2026-06-01')
    db = make_db(tmp_path, cfg)
    evaluate(db)
    first = forecast(db)
    assert first['subjects']['D']['audit']['review_date'] == '2026-01-31'
    revised = dict(cfg)
    revised['rule_version'] = 'v2'
    revised['policy'] = {'ordinary': {'start': 'created', 'days': 365}}
    p = tmp_path / 'v2.json'
    p.write_text(json.dumps(revised), encoding='utf-8')
    action('recheck', db, out=p)
    second = forecast(db)
    assert second['anchored_run'] != first['anchored_run']
    assert second['subjects']['D']['audit']['review_date'] == '2027-01-01'  # 2026-01-01 + 365 天
    con = connect(db)
    assert con.execute('SELECT count(*) FROM forecast_run').fetchone()[0] == 2
    old = con.execute('SELECT review_date FROM forecast WHERE forecast_run_id=? AND subject=? AND contract=?',
                      (first['forecast_run'], 'D', 'audit')).fetchone()
    assert old[0] == '2026-01-31'


def test_tagged_hold_and_dependency_evidence_change_forecast(tmp_path):
    db = demo_db(tmp_path)
    feed(tmp_path, db, [{'event_key': 'scope-1', 'subject': 'B', 'kind': 'hold_start',
                         'hold_id': 'court-scope', 'scope_tag': 'regulated', 'at': '2026-03-01'}],
         name='scope.jsonl')
    r = forecast(db)['subjects']['D']
    assert r['audit']['level'] == '无法预报'
    assert r['operational']['level'] == '有条件'
    assert any('court-scope' in p for p in r['operational']['premises'])


def test_report_lists_forecasts_with_premises_and_chain(tmp_path):
    cfg = cfg_for({'C': {'created': '2026-01-01', 'category': 'active', 'path': 'C.bin'}})
    db = make_db(tmp_path, cfg, [
        {'event_key': 'u1', 'subject': 'C', 'kind': 'use', 'at': '2026-06-01'},
        {'event_key': 'u2', 'subject': 'C', 'kind': 'use', 'at': '2026-06-20'}])
    evaluate(db)
    forecast(db)
    out = export(db, tmp_path / 'report.json')
    data = json.loads(out.read_text(encoding='utf-8'))
    assert data['forecasts'] and data['forecasts'][0]['items']
    fr = data['forecasts'][0]['forecast_run']
    assert fr['rule_version'] == 'v1' and fr['as_of'] == '2026-06-10'
    item = [i for i in data['forecasts'][0]['items']
            if i['subject'] == 'C' and i['contract'] == 'operational'][0]
    assert item['level'] == '有条件' and item['review_date'] == '2026-07-20'
    detail = json.loads(item['detail'])
    assert detail['rule_version'] == 'v1' and detail['premises']
    assert detail['basis']['start_events'] and 'dependency_chain' in detail
    md = out.with_suffix('.md').read_text(encoding='utf-8')
    assert '复核' in md and '不构成可销毁授权' in md
    assert verify(db) == []


def test_forecast_rejects_tampered_config(tmp_path):
    db = demo_db(tmp_path)
    con = connect(db)
    cfg = json.loads(con.execute('SELECT config_raw FROM batch').fetchone()[0])
    cfg['policy']['active']['days'] = 999
    con.execute('UPDATE batch SET config_raw=?', (json.dumps(cfg).encode(),))
    con.commit()
    con.close()
    with pytest.raises(ValueError, match='batch_config_tampered'):
        forecast(db)


def test_forecast_without_evaluate_run(tmp_path):
    cfg = cfg_for({'D': {'created': '2026-01-01', 'category': 'ordinary', 'path': 'D.bin'}},
                  as_of='2026-06-01')
    db = make_db(tmp_path, cfg)
    result = forecast(db)
    assert result['anchored_run'] is None
    assert result['subjects']['D']['audit']['review_date'] == '2026-01-31'


def test_cli_forecast(tmp_path):
    db = demo_db(tmp_path)
    evaluate(db)
    out = subprocess.run([sys.executable, '-m', 'retaincase', 'forecast', '--db', str(db)],
                         capture_output=True, text=True, cwd=ROOT)
    assert out.returncode == 0, out.stderr
    assert '保证到期' in out.stdout and '无法预报' in out.stdout
    out2 = subprocess.run([sys.executable, '-m', 'retaincase', 'forecast', '--db', str(db),
                           '--contract', 'audit'], capture_output=True, text=True, cwd=ROOT)
    assert out2.returncode == 0, out2.stderr
    con = connect(db)
    assert con.execute('SELECT count(*) FROM forecast_run').fetchone()[0] == 2
    assert con.execute("SELECT count(*) FROM forecast WHERE contract='operational'").fetchone()[0] == 4
