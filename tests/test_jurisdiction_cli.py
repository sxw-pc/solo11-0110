import json
import subprocess
import sys
from pathlib import Path

FIX = Path(__file__).resolve().parents[1] / 'fixtures'


def run(*args, cwd):
    return subprocess.run([sys.executable, '-m', 'retaincase', *args], cwd=cwd,
                          capture_output=True, text=True, check=True).stdout.strip()


def test_cli_jurisdiction_workflow(tmp_path):
    root = Path(__file__).resolve().parents[1]
    db = tmp_path / 'j.db'
    run('init', '--db', str(db), '--config', str(FIX / 'jurisdiction-config.json'), cwd=root)
    run('load', '--db', str(db), str(FIX / 'jurisdiction-events.jsonl'), cwd=root)
    assert run('evaluate', '--db', str(db), '--contract', 'concurrent',
               '--authority', 'memo-7', cwd=root) == "{'D': '冻结'}"
    report = tmp_path / 'r.json'
    run('report', '--db', str(db), '--out', str(report), cwd=root)
    assert run('verify', '--db', str(db), cwd=root) == "{'integrity_problems': [], 'target': []}"
    data = json.loads(report.read_text(encoding='utf-8'))
    assert data['contract']['contract'] == 'concurrent'
    assert data['decisions'][0]['status'] == '冻结'
    assert {r['jurisdiction'] for r in data['jurisdictions']['D']} == {'J1', 'J2'}
    assert run('evaluate', '--db', str(db), '--contract', 'single_successor',
               '--authority', 'memo-7', cwd=root) == "{'D': '可销毁'}"
