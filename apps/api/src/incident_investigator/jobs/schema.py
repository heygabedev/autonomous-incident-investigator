"""Additive, transactionally versioned local schema. Never downgrade persisted data."""

import sqlite3
import uuid

from incident_investigator.evaluation.canonical import content_digest
from incident_investigator.security.authority import SecurityAuthority
from incident_investigator.security.storage import private_file

STATEMENTS = (
    "CREATE TABLE jobs (id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, "
    "fingerprint TEXT NOT NULL, initial BLOB NOT NULL CHECK(length(initial)<=1048576), "
    "policy BLOB NOT NULL CHECK(length(policy)<=1048576), "
    "view BLOB NOT NULL CHECK(length(view)<=1048576), "
    "lease_token TEXT, lease_until INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE job_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, "
    "job_id TEXT NOT NULL, payload BLOB NOT NULL CHECK(length(payload)<=1048576))",
    "CREATE INDEX job_events_by_job ON job_events(job_id, sequence)",
)
SCHEMA_DIGEST = content_digest(list(STATEMENTS))


def migrate(authority: SecurityAuthority) -> None:
    with authority.connect() as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS job_migrations (version INTEGER PRIMARY KEY, "
            "digest TEXT NOT NULL)"
        )
        rows = connection.execute("SELECT version, digest FROM job_migrations").fetchall()
        if rows:
            if rows != [(1, SCHEMA_DIGEST)]:
                raise ValueError("unsupported_job_schema")
            return
    # Restore goes into a new target. Never overwrite a previous backup or the live DB.
    path = private_file(authority.root / f"before-jobs-v1-{uuid.uuid4().hex}.sqlite3")
    with authority.connect() as source:
        target = sqlite3.connect(path)
        try:
            source.backup(target)
            if target.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise ValueError("backup_integrity_failure")
        finally:
            target.close()
    with authority.connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute("SELECT version, digest FROM job_migrations").fetchall()
        if rows:
            if rows != [(1, SCHEMA_DIGEST)]:
                raise ValueError("unsupported_job_schema")
            return
        for statement in STATEMENTS:
            connection.execute(statement)
        connection.execute("INSERT INTO job_migrations VALUES (1, ?)", (SCHEMA_DIGEST,))
