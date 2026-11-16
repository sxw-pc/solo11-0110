import json
from pathlib import Path

import pytest

from retaincase.ingest import initialize, load
from retaincase.rules import evaluate
from retaincase.storage import inventory, load_fixture, place, register_pool

FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures'


def ready_db(tmp_path):
    db = tmp_path / 'ledger.db'
    initialize(db, FIXTURES / 'config.json')
    load(db, FIXTURES / 'events.jsonl')
    evaluate(db)
    return db


def test_storage_fixture_and_idempotence(tmp_path):
    db = ready_db(tmp_path)
    first = load_fixture(db, FIXTURES / 'storage-placement.json')
    second = load_fixture(db, FIXTURES / 'storage-placement.json')
    assert first == second == inventory(db)
    assert [row['subject'] for row in first['placements']] == ['A', 'B']
    assert sum(row['bytes'] for row in first['placements']) == 70


def test_storage_only_for_retained_and_within_capacity(tmp_path):
    db = ready_db(tmp_path)
    row = json.loads((FIXTURES / 'storage-placement.json').read_text(encoding='utf-8'))['placements'][0]
    register_pool(db, 'small', 20)
    with pytest.raises(ValueError, match='storage_pool_full'):
        place(db, 'A', 'small', row['bytes'], row['inventory_digest'])
    with pytest.raises(ValueError, match='storage_placement_requires_retained_object'):
        place(db, 'D', 'small', 10, row['inventory_digest'])
    assert inventory(db)['placements'] == []
