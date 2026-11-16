"""Local retained-object storage placement, independent of erasure execution."""
import json
from .store import connect

SCHEMA = """
CREATE TABLE IF NOT EXISTS storage_pool(
 id TEXT PRIMARY KEY, capacity_bytes INTEGER NOT NULL CHECK(capacity_bytes>0));
CREATE TABLE IF NOT EXISTS storage_placement(
 subject TEXT PRIMARY KEY REFERENCES subject(id), pool_id TEXT NOT NULL REFERENCES storage_pool(id),
 bytes INTEGER NOT NULL CHECK(bytes>0), inventory_digest TEXT NOT NULL,
 decision_run_id INTEGER NOT NULL REFERENCES run(id));
"""

def register_pool(db_path, pool_id, capacity_bytes):
    if not pool_id or not isinstance(capacity_bytes, int) or isinstance(capacity_bytes, bool) or capacity_bytes <= 0:
        raise ValueError('invalid_storage_pool')
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        old = db.execute('SELECT capacity_bytes FROM storage_pool WHERE id=?', (pool_id,)).fetchone()
        if old and old['capacity_bytes'] != capacity_bytes:
            raise ValueError('storage_pool_identity_conflict')
        with db:
            db.execute('INSERT OR IGNORE INTO storage_pool VALUES (?,?)', (pool_id, capacity_bytes))
        return {'pool': pool_id, 'capacity_bytes': capacity_bytes}
    finally:
        db.close()

def place(db_path, subject, pool_id, size_bytes, inventory_digest):
    if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes <= 0 or not isinstance(inventory_digest, str) or len(inventory_digest) != 64:
        raise ValueError('invalid_storage_inventory')
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        db.execute('BEGIN IMMEDIATE')
        pool = db.execute('SELECT capacity_bytes FROM storage_pool WHERE id=?', (pool_id,)).fetchone()
        run = db.execute('SELECT max(id) AS id FROM run').fetchone()['id']
        decision = db.execute('SELECT status FROM decision WHERE run_id=? AND subject=?', (run, subject)).fetchone()
        if not pool or not decision or decision['status'] != '冻结':
            raise ValueError('storage_placement_requires_retained_object')
        if db.execute("SELECT 1 FROM execution WHERE subject=? AND action='destroy'", (subject,)).fetchone():
            raise ValueError('storage_object_destroyed')
        old = db.execute('SELECT * FROM storage_placement WHERE subject=?', (subject,)).fetchone()
        if old:
            if (old['pool_id'],old['bytes'],old['inventory_digest']) != (pool_id,size_bytes,inventory_digest):
                raise ValueError('storage_placement_identity_conflict')
            db.commit()
            return dict(old)
        used = db.execute('SELECT COALESCE(sum(bytes),0) FROM storage_placement WHERE pool_id=?', (pool_id,)).fetchone()[0]
        if used + size_bytes > pool['capacity_bytes']:
            raise ValueError('storage_pool_full')
        db.execute('INSERT INTO storage_placement VALUES (?,?,?,?,?)', (subject,pool_id,size_bytes,inventory_digest,run))
        db.commit()
        return {'subject':subject,'pool_id':pool_id,'bytes':size_bytes,'inventory_digest':inventory_digest,'decision_run_id':run}
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def inventory(db_path):
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        return {'pools':[dict(x) for x in db.execute('SELECT * FROM storage_pool ORDER BY id')],
                'placements':[dict(x) for x in db.execute('SELECT * FROM storage_placement ORDER BY subject')]}
    finally:
        db.close()

def load_fixture(db_path, fixture_path):
    from pathlib import Path
    fixture = json.loads(Path(fixture_path).read_text(encoding='utf-8'))
    for row in fixture['pools']:
        register_pool(db_path, row['id'], row['capacity_bytes'])
    for row in fixture['placements']:
        place(db_path, row['subject'], row['pool_id'], row['bytes'], row['inventory_digest'])
    return inventory(db_path)
