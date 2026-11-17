from pathlib import Path

import pytest

from retaincase import ingest, rules, usage


FIXTURE = Path(__file__).resolve().parents[1] / 'fixtures'


def test_usage_registers_scans_without_changing_retention(tmp_path):
    db = tmp_path / 'ledger.db'
    ingest.initialize(db, FIXTURE / 'config.json')
    ingest.load(db, FIXTURE / 'events.jsonl')
    original = rules.evaluate(db)
    digest = usage.register(db, 'shift-1', FIXTURE / 'usage-scans.jsonl')
    assert usage.register(db, 'shift-1', FIXTURE / 'usage-scans.jsonl') == digest
    assert usage.summary(db, 'shift-1') == {'scans': 4, 'actors': 1, 'devices': 2}
    assert rules.evaluate(db) == original


def test_usage_log_identity_is_immutable(tmp_path):
    db = tmp_path / 'ledger.db'
    ingest.initialize(db, FIXTURE / 'config.json')
    usage.register(db, 'shift-1', FIXTURE / 'usage-scans.jsonl')
    changed = tmp_path / 'changed.jsonl'
    changed.write_bytes((FIXTURE / 'usage-scans.jsonl').read_bytes().replace(b'operator-1', b'operator-2'))
    with pytest.raises(ValueError, match='usage_log_identity_conflict'):
        usage.register(db, 'shift-1', changed)
