"""Register a field-level inventory of retained local data."""
import csv
import hashlib
import json
from pathlib import Path

from .store import connect


SCHEMA = """
CREATE TABLE IF NOT EXISTS minimization_inventory(
  inventory_id TEXT PRIMARY KEY, source_hash TEXT NOT NULL,
  row_count INTEGER NOT NULL, state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS minimization_field(
  inventory_id TEXT NOT NULL REFERENCES minimization_inventory(inventory_id),
  subject TEXT NOT NULL, field TEXT NOT NULL, value TEXT NOT NULL,
  classification TEXT NOT NULL,
  PRIMARY KEY(inventory_id,subject,field));
"""


def register(db_path, inventory_id, csv_path):
    """Freeze an inventory receipt without changing the retained source file."""
    if not isinstance(inventory_id, str) or not inventory_id:
        raise ValueError('inventory_id_required')
    source = Path(csv_path)
    raw = source.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    with source.open('r', encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != ['subject', 'field', 'value', 'classification']:
            raise ValueError('inventory_columns_invalid')
        rows = list(reader)
    if not rows:
        raise ValueError('inventory_empty')
    if any(not all(row.values()) or row['classification'] not in
           {'direct', 'derived', 'public'} for row in rows):
        raise ValueError('inventory_row_invalid')
    keys = [(row['subject'], row['field']) for row in rows]
    if len(set(keys)) != len(keys):
        raise ValueError('inventory_field_duplicate')
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        batch = db.execute('SELECT config_raw FROM batch LIMIT 1').fetchone()
        if not batch:
            raise ValueError('inventory_requires_batch')
        subjects = json.loads(batch['config_raw'])['subjects']
        if any(row['subject'] not in subjects for row in rows):
            raise ValueError('inventory_unknown_subject')
        prior = db.execute('SELECT source_hash,row_count FROM minimization_inventory WHERE inventory_id=?',
                           (inventory_id,)).fetchone()
        if prior:
            if (prior['source_hash'], prior['row_count']) != (digest, len(rows)):
                raise ValueError('inventory_identity_conflict')
        else:
            with db:
                db.execute('INSERT INTO minimization_inventory VALUES (?,?,?,?)',
                           (inventory_id, digest, len(rows), 'registered'))
                db.executemany('INSERT INTO minimization_field VALUES (?,?,?,?,?)', [
                    (inventory_id, row['subject'], row['field'], row['value'],
                     row['classification']) for row in rows
                ])
        return {'inventory_id': inventory_id, 'source_hash': digest,
                'row_count': len(rows), 'state': 'registered'}
    finally:
        db.close()


def inspect(db_path, inventory_id):
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        receipt = db.execute('SELECT * FROM minimization_inventory WHERE inventory_id=?',
                             (inventory_id,)).fetchone()
        if not receipt:
            raise ValueError('unknown_inventory')
        fields = [dict(row) for row in db.execute(
            'SELECT subject,field,value,classification FROM minimization_field '
            'WHERE inventory_id=? ORDER BY subject,field', (inventory_id,))]
        return {'receipt': dict(receipt), 'fields': fields}
    finally:
        db.close()
