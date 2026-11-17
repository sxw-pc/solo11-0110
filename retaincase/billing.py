"""Freeze a synthetic retained-object storage meter and report its pooled bill."""
import hashlib
import json
from pathlib import Path

from .store import connect


def register(db_path, meter_id, source_path):
    if not isinstance(meter_id, str) or not meter_id:
        raise ValueError('bad_meter_id')
    raw = Path(source_path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    body = json.loads(raw)
    if not isinstance(body, dict) or not isinstance(body.get('blobs'), list) or not body['blobs']:
        raise ValueError('bad_meter')
    tiers = body.get('tariff_cents_per_byte')
    if not isinstance(tiers, list) or len(tiers) != 2 or any(type(x) is not int or x < 0 for x in tiers):
        raise ValueError('bad_tariff')
    cap = body.get('first_tier_bytes')
    if type(cap) is not int or cap <= 0:
        raise ValueError('bad_first_tier')
    rows = []
    seen = set()
    for item in body['blobs']:
        blob_id, subject, size, matters = (item[k] for k in ('blob_id', 'subject', 'bytes', 'matters'))
        if not isinstance(blob_id, str) or not blob_id or blob_id in seen or not isinstance(subject, str) \
                or type(size) is not int or size <= 0 or not isinstance(matters, list) \
                or not matters or any(not isinstance(m, str) or not m for m in matters) \
                or len(matters) != len(set(matters)):
            raise ValueError('bad_meter_blob')
        seen.add(blob_id)
        rows.append((meter_id, blob_id, subject, size, json.dumps(sorted(matters))))
    db = connect(db_path)
    try:
        with db:
            batch = db.execute('SELECT id FROM batch LIMIT 1').fetchone()
            if not batch:
                raise ValueError('initialize_first')
            old = db.execute('SELECT source_hash FROM storage_meter WHERE id=?', (meter_id,)).fetchone()
            if old:
                if old['source_hash'] != digest:
                    raise ValueError('meter_identity_conflict')
                return digest
            for _, _, subject, _, _ in rows:
                if not db.execute('SELECT 1 FROM subject WHERE id=? AND batch_id=?',
                                  (subject, batch['id'])).fetchone():
                    raise ValueError('unknown_meter_subject')
            db.execute('INSERT INTO storage_meter VALUES (?,?,?,?)', (meter_id, batch['id'], digest, raw))
            db.executemany('INSERT INTO storage_blob VALUES (?,?,?,?,?)', rows)
            return digest
    finally:
        db.close()


def summary(db_path, meter_id):
    """A pooled census and total bill, with no matter-level attribution."""
    db = connect(db_path)
    try:
        row = db.execute('SELECT raw,source_hash FROM storage_meter WHERE id=?', (meter_id,)).fetchone()
        if not row:
            raise ValueError('unknown_meter')
        body = json.loads(row['raw'])
        blobs = db.execute('SELECT bytes,matters_json FROM storage_blob WHERE meter_id=?',
                           (meter_id,)).fetchall()
        total = sum(r['bytes'] for r in blobs)
        matters = {m for r in blobs for m in json.loads(r['matters_json'])}
        first = min(total, body['first_tier_bytes'])
        bill = first * body['tariff_cents_per_byte'][0] \
            + (total - first) * body['tariff_cents_per_byte'][1]
        return {'blobs': len(blobs), 'matters': len(matters), 'unique_bytes': total,
                'pooled_cents': bill, 'source_hash': row['source_hash']}
    finally:
        db.close()
