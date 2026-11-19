"""Local retained-object storage placement, independent of erasure execution."""
import json
from pathlib import Path

from .store import connect

SCHEMA = """
CREATE TABLE IF NOT EXISTS storage_pool(
 id TEXT PRIMARY KEY,
 capacity_bytes INTEGER NOT NULL CHECK(capacity_bytes>0),
 failure_domain TEXT NOT NULL,
 tier TEXT NOT NULL CHECK(tier IN ('warm','cold')));
CREATE TABLE IF NOT EXISTS storage_placement(
 subject TEXT PRIMARY KEY REFERENCES subject(id), pool_id TEXT NOT NULL REFERENCES storage_pool(id),
 bytes INTEGER NOT NULL CHECK(bytes>0), inventory_digest TEXT NOT NULL,
 decision_run_id INTEGER NOT NULL REFERENCES run(id));
"""

TIERS = ('warm', 'cold')


def _migrate(db):
    """Add failure-domain columns to a ledger created by the placement baseline."""
    cols = {r['name'] for r in db.execute('PRAGMA table_info(storage_pool)')}
    if cols and 'failure_domain' not in cols:
        db.execute("ALTER TABLE storage_pool ADD COLUMN failure_domain TEXT NOT NULL DEFAULT ''")
        db.execute("UPDATE storage_pool SET failure_domain=id WHERE failure_domain=''")
    if cols and 'tier' not in cols:
        db.execute("ALTER TABLE storage_pool ADD COLUMN tier TEXT NOT NULL DEFAULT 'warm'")


def _valid_pool_id(pool_id):
    if not isinstance(pool_id, str) or not pool_id:
        return False
    parts = Path(pool_id).parts
    return pool_id not in ('.', '..') and '..' not in parts and '/' not in pool_id and '\\' not in pool_id


def register_pool(db_path, pool_id, capacity_bytes, failure_domain=None, tier='warm'):
    if not _valid_pool_id(pool_id) or not isinstance(capacity_bytes, int) or isinstance(capacity_bytes, bool) or capacity_bytes <= 0:
        raise ValueError('invalid_storage_pool')
    if tier not in TIERS:
        raise ValueError('invalid_storage_tier')
    domain = failure_domain if failure_domain is not None else pool_id
    if not isinstance(domain, str) or not domain:
        raise ValueError('invalid_failure_domain')
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        _migrate(db)
        old = db.execute('SELECT capacity_bytes,failure_domain,tier FROM storage_pool WHERE id=?', (pool_id,)).fetchone()
        if old and (old['capacity_bytes'] != capacity_bytes or old['failure_domain'] != domain or old['tier'] != tier):
            raise ValueError('storage_pool_identity_conflict')
        with db:
            db.execute('INSERT OR IGNORE INTO storage_pool(id,capacity_bytes,failure_domain,tier) VALUES (?,?,?,?)',
                       (pool_id, capacity_bytes, domain, tier))
        return {'pool': pool_id, 'capacity_bytes': capacity_bytes, 'failure_domain': domain, 'tier': tier}
    finally:
        db.close()

def place(db_path, subject, pool_id, size_bytes, inventory_digest):
    if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes <= 0 or not isinstance(inventory_digest, str) or len(inventory_digest) != 64:
        raise ValueError('invalid_storage_inventory')
    db = connect(db_path)
    try:
        db.executescript(SCHEMA)
        _migrate(db)
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
        _migrate(db)
        return {'pools':[dict(x) for x in db.execute('SELECT * FROM storage_pool ORDER BY id')],
                'placements':[dict(x) for x in db.execute('SELECT * FROM storage_placement ORDER BY subject')]}
    finally:
        db.close()

def load_fixture(db_path, fixture_path):
    fixture = json.loads(Path(fixture_path).read_text(encoding='utf-8'))
    for row in fixture['pools']:
        register_pool(db_path, row['id'], row['capacity_bytes'],
                      failure_domain=row.get('failure_domain'), tier=row.get('tier', 'warm'))
    for row in fixture['placements']:
        place(db_path, row['subject'], row['pool_id'], row['bytes'], row['inventory_digest'])
    return inventory(db_path)
