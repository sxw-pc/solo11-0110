from pathlib import Path

import pytest

from retaincase import billing
from retaincase.ingest import initialize


FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures'


def test_pooled_bill_without_matter_attribution(tmp_path):
    db = tmp_path / 'meter.db'
    initialize(db, FIXTURES / 'config.json')
    digest = billing.register(db, 'meter-1', FIXTURES / 'storage-meter.json')
    assert billing.summary(db, 'meter-1') == {
        'blobs': 2, 'matters': 2, 'unique_bytes': 200, 'pooled_cents': 300,
        'source_hash': digest}
    assert billing.register(db, 'meter-1', FIXTURES / 'storage-meter.json') == digest


def test_meter_identity_conflict(tmp_path):
    db = tmp_path / 'meter.db'
    initialize(db, FIXTURES / 'config.json')
    billing.register(db, 'meter-1', FIXTURES / 'storage-meter.json')
    altered = tmp_path / 'altered.json'
    altered.write_bytes((FIXTURES / 'storage-meter.json').read_bytes() + b' ')
    with pytest.raises(ValueError, match='meter_identity_conflict'):
        billing.register(db, 'meter-1', altered)
