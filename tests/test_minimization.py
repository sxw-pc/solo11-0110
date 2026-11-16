from pathlib import Path

import pytest

from retaincase.ingest import initialize
from retaincase.minimization import inspect, register


FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures'


def test_register_inventory_idempotent(tmp_path):
    db = tmp_path / 'control.db'
    initialize(db, FIXTURES / 'config.json')
    first = register(db, 'min-01', FIXTURES / 'minimization-inventory.csv')
    assert first == register(db, 'min-01', FIXTURES / 'minimization-inventory.csv')
    record = inspect(db, 'min-01')
    assert record['receipt']['row_count'] == 6
    assert record['fields'][0]['subject'] == 'A'


def test_unknown_subject_and_changed_identity(tmp_path):
    db = tmp_path / 'control.db'
    initialize(db, FIXTURES / 'config.json')
    original = FIXTURES / 'minimization-inventory.csv'
    register(db, 'min-01', original)
    changed = tmp_path / 'changed.csv'
    changed.write_text(original.read_text(encoding='utf-8').replace('contact-A', 'new-A'),
                       encoding='utf-8')
    with pytest.raises(ValueError, match='inventory_identity_conflict'):
        register(db, 'min-01', changed)
    changed.write_text(original.read_text(encoding='utf-8').replace('A,contact', 'Z,contact'),
                       encoding='utf-8')
    with pytest.raises(ValueError, match='inventory_unknown_subject'):
        register(db, 'other', changed)
