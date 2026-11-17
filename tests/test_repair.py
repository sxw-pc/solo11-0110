from pathlib import Path

import pytest

from retaincase.ingest import initialize
from retaincase import repair


FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures'


def test_repair_census(tmp_path):
    db = tmp_path / 'repair.db'
    initialize(db, FIXTURES / 'config.json')
    digest = repair.register(db, 'r1', FIXTURES / 'repair-incidents.json')
    assert repair.summary(db, 'r1') == {'incidents': 2, 'options': 3,
                                         'source_hash': digest}
    assert repair.register(db, 'r1', FIXTURES / 'repair-incidents.json') == digest


def test_repair_identity_conflict(tmp_path):
    db = tmp_path / 'repair.db'
    initialize(db, FIXTURES / 'config.json')
    repair.register(db, 'r1', FIXTURES / 'repair-incidents.json')
    changed = tmp_path / 'changed.json'
    changed.write_bytes((FIXTURES / 'repair-incidents.json').read_bytes() + b' ')
    with pytest.raises(ValueError, match='repair_batch_identity_conflict'):
        repair.register(db, 'r1', changed)
