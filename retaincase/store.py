import sqlite3
from pathlib import Path
SCHEMA="""
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS batch(id TEXT PRIMARY KEY, config_hash TEXT NOT NULL, config_raw BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS source_file(id INTEGER PRIMARY KEY, batch_id TEXT NOT NULL REFERENCES batch(id), name TEXT NOT NULL, digest TEXT NOT NULL, raw BLOB NOT NULL, UNIQUE(batch_id,digest));
CREATE TABLE IF NOT EXISTS raw_event(id INTEGER PRIMARY KEY, source_id INTEGER NOT NULL REFERENCES source_file(id), line_no INTEGER NOT NULL, event_key TEXT NOT NULL, subject TEXT NOT NULL, kind TEXT NOT NULL, at TEXT, payload TEXT NOT NULL, digest TEXT NOT NULL, UNIQUE(source_id,line_no));
CREATE TABLE IF NOT EXISTS subject(id TEXT PRIMARY KEY, batch_id TEXT NOT NULL REFERENCES batch(id));
CREATE TABLE IF NOT EXISTS rule_version(id TEXT PRIMARY KEY, body TEXT NOT NULL, digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS run(id INTEGER PRIMARY KEY, batch_id TEXT NOT NULL REFERENCES batch(id), status TEXT NOT NULL, started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, ended_at TEXT);
CREATE TABLE IF NOT EXISTS issue(id INTEGER PRIMARY KEY, run_id INTEGER REFERENCES run(id), source_id INTEGER REFERENCES source_file(id), line_no INTEGER, subject TEXT, code TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES run(id), subject TEXT NOT NULL, source_id INTEGER REFERENCES source_file(id), event_id INTEGER REFERENCES raw_event(id), rule_id TEXT REFERENCES rule_version(id), detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS decision(id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES run(id), subject TEXT NOT NULL, status TEXT NOT NULL, detail TEXT NOT NULL, UNIQUE(run_id,subject));
CREATE TABLE IF NOT EXISTS execution(id INTEGER PRIMARY KEY, run_id INTEGER REFERENCES run(id), subject TEXT NOT NULL, action TEXT NOT NULL, before_hash TEXT, after_state TEXT NOT NULL, at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(subject,action,before_hash));
CREATE TABLE IF NOT EXISTS plan(id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES run(id), digest TEXT NOT NULL UNIQUE, body TEXT NOT NULL);

-- Recovery-aware local execution attempts.  The legacy `execution` table above
-- is deliberately left untouched: those rows are legacy-protocol records and
-- are never interpreted as recoverable quarantine evidence.  New attempts keep
-- their own frozen manifest, per-object state journal and final proofs.
CREATE TABLE IF NOT EXISTS execution_attempt(
 id TEXT PRIMARY KEY,
 plan_digest TEXT NOT NULL,
 run_id INTEGER NOT NULL REFERENCES run(id),
 sandbox TEXT NOT NULL,
 recovery_policy TEXT NOT NULL CHECK(recovery_policy IN ('complete_on_recovery','restore_on_recovery')),
 state TEXT NOT NULL CHECK(state IN ('prepared','quarantining','quarantined','disposing','complete','restoring','restored','partial','disputed','stale')),
 manifest TEXT NOT NULL,
 manifest_digest TEXT NOT NULL,
 detail TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS execution_object(
 attempt_id TEXT NOT NULL REFERENCES execution_attempt(id),
 ordinal INTEGER NOT NULL,
 subject TEXT NOT NULL,
 original_path TEXT NOT NULL,
 expected_hash TEXT NOT NULL,
 quarantine_path TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','moving','quarantined','destroying','destroyed','restored','disputed')),
 observed_hash TEXT,
 reason TEXT,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(attempt_id,subject),
 UNIQUE(attempt_id,original_path),
 UNIQUE(attempt_id,ordinal));
CREATE TABLE IF NOT EXISTS execution_event(
 id INTEGER PRIMARY KEY,
 attempt_id TEXT NOT NULL REFERENCES execution_attempt(id),
 seq INTEGER NOT NULL,
 kind TEXT NOT NULL,
 subject TEXT,
 detail TEXT NOT NULL,
 at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(attempt_id,seq));
CREATE TABLE IF NOT EXISTS execution_proof(
 id INTEGER PRIMARY KEY,
 attempt_id TEXT NOT NULL REFERENCES execution_attempt(id),
 run_id INTEGER NOT NULL REFERENCES run(id),
 subject TEXT NOT NULL,
 plan_digest TEXT NOT NULL,
 before_hash TEXT NOT NULL,
 after_state TEXT NOT NULL CHECK(after_state='absent'),
 at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(attempt_id,subject));
-- An active claim prevents two plans (or two concurrent processes) from
-- operating on the same object.  Claims are released only once the attempt has
-- reached a final state whose file disposition is fully settled.
CREATE TABLE IF NOT EXISTS execution_claim(
 sandbox TEXT NOT NULL,
 original_path TEXT NOT NULL,
 attempt_id TEXT NOT NULL REFERENCES execution_attempt(id),
 acquired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(sandbox,original_path));
CREATE UNIQUE INDEX IF NOT EXISTS execution_one_active_plan
 ON execution_attempt(sandbox,plan_digest)
 WHERE state IN ('prepared','quarantining','quarantined','disposing');
"""
def connect(path):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(path);db.row_factory=sqlite3.Row;db.executescript(SCHEMA);return db
