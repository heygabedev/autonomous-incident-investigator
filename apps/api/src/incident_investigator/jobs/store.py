import sqlite3
import time
from collections.abc import Callable
from typing import Any

from incident_investigator.evaluation.canonical import canonical_bytes, content_digest, parse_json
from incident_investigator.jobs.contracts import JobError, JobEvent, JobView
from incident_investigator.jobs.schema import migrate
from incident_investigator.security.authority import AuditEvent, SecurityAuthority
from incident_investigator.security.policy import SecurityPolicy
from incident_investigator.workflow.contracts import RunState
from incident_investigator.workflow.graph import validate_state


def encoded(value: JobView | RunState | SecurityPolicy) -> bytes:
    return canonical_bytes(parse_json(value.model_dump_json()))


class JobStore:
    def __init__(
        self, authority: SecurityAuthority, clock: Callable[[], int] | None = None
    ) -> None:
        self.authority = authority
        self.clock = clock or (lambda: int(time.time()))
        migrate(authority)

    def audit(self, connection: sqlite3.Connection, actor: str, action: str, job: JobView) -> None:
        self.authority._append(
            connection,
            AuditEvent(
                actor_id=actor,
                action=action,
                decision="allow",
                reason="local_fixture",
                policy_revision=self.authority._read(connection).revision,
                artifact_ids=(job.id, job.pin.candidate_id),
            ),
        )

    def write(self, connection: sqlite3.Connection, job: JobView) -> None:
        payload = encoded(job)
        connection.execute("UPDATE jobs SET view=? WHERE id=?", (payload, job.id))
        connection.execute(
            "INSERT INTO job_events(job_id, payload) VALUES (?, ?)", (job.id, payload)
        )

    def changed(self, job: JobView, **values: Any) -> JobView:
        return JobView.model_validate_json(
            canonical_bytes(
                {
                    **job.model_dump(mode="json"),
                    **values,
                    "revision": job.revision + 1,
                    "updated_at": self.clock(),
                }
            )
        )

    @staticmethod
    def read(connection: sqlite3.Connection, identifier: str) -> JobView:
        row = connection.execute("SELECT view FROM jobs WHERE id=?", (identifier,)).fetchone()
        if row is None:
            raise JobError(404, "job_not_found")
        job = JobView.model_validate_json(canonical_bytes(parse_json(row[0])))
        if job.id != identifier:
            raise ValueError("job_integrity_failure")
        return job

    def get(self, identifier: str) -> JobView:
        with self.authority.connect() as connection:
            return self.read(connection, identifier)

    def recent(self) -> tuple[JobView, ...]:
        with self.authority.connect() as connection:
            rows = connection.execute("SELECT id FROM jobs ORDER BY rowid DESC LIMIT 50").fetchall()
            return tuple(self.read(connection, row[0]) for row in rows)

    def initial(self, identifier: str) -> tuple[RunState, SecurityPolicy]:
        with self.authority.connect() as connection:
            job = self.read(connection, identifier)
            row = connection.execute(
                "SELECT initial, policy FROM jobs WHERE id=?", (identifier,)
            ).fetchone()
        state = RunState.model_validate_json(canonical_bytes(parse_json(row[0])))
        policy = SecurityPolicy.model_validate_json(canonical_bytes(parse_json(row[1])))
        validate_state(state, job.pin)
        if (
            state.attempt_id != job.id
            or state.input_digest != job.input_digest
            or state.completed
            or state.next_stage != "scope"
            or content_digest(parse_json(policy.model_dump_json())) != job.pin.policy_digest
        ):
            raise ValueError("job_integrity_failure")
        return state, policy

    def check_lineage(self, connection: sqlite3.Connection, job: JobView) -> None:
        restrictions = self.authority.read()
        seen = {job.id}
        child = job
        while child.replay_of is not None:
            if child.replay_of in seen or len(seen) >= 1000:
                raise ValueError("invalid_job_lineage")
            parent = self.read(connection, child.replay_of)
            seen.add(parent.id)
            if (
                parent.recall_reason in ("security_review", "invalidated_evidence")
                or parent.pin.candidate_id in restrictions.revoked_candidates
            ):
                raise JobError(409, "replay_source_restricted")
            if (
                parent.recall_reason == "defective_runtime"
                and parent.pin.graph_digest == child.pin.graph_digest
            ):
                raise JobError(409, "replay_requires_changed_runtime")
            child = parent

    def submit(
        self,
        state: RunState,
        policy: SecurityPolicy,
        key: str,
        fingerprint: str,
        actor: str,
        replay_of: str | None = None,
    ) -> JobView:
        job = JobView(
            id=state.attempt_id,
            pin=state.pin,
            input_digest=state.input_digest,
            created_at=self.clock(),
            updated_at=self.clock(),
            replay_of=replay_of,
        )
        with self.authority.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT id, fingerprint FROM jobs WHERE idempotency_key=?", (key,)
            ).fetchone()
            if row is not None:
                if row[1] != fingerprint:
                    raise JobError(409, "idempotency_conflict")
                return self.read(connection, row[0])
            restrictions = self.authority.read()
            if restrictions.safe_mode:
                raise JobError(409, "contained")
            if state.pin.candidate_id in restrictions.revoked_candidates:
                raise JobError(403, "candidate_revoked")
            # Explicit bounded storage/queue. Retention and archival are a later subsystem.
            count = connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
            pending = connection.execute(
                "SELECT COUNT(*) FROM jobs WHERE json_extract(view, '$.status') "
                "IN ('queued', 'running')"
            ).fetchone()[0]
            if count >= 1000 or pending >= 32:
                raise JobError(429, "queue_capacity")
            if replay_of is not None:
                parent = self.read(connection, replay_of)
                if parent.status not in ("succeeded", "failed", "cancelled"):
                    raise JobError(409, "replay_requires_terminal_job")
                self.check_lineage(connection, job)
            self.audit(connection, actor, "job.submit", job)
            connection.execute(
                "INSERT INTO jobs(id, idempotency_key, fingerprint, initial, policy, view) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (job.id, key, fingerprint, encoded(state), encoded(policy), encoded(job)),
            )
            self.write(connection, job)
        return job

    def events(self, identifier: str, after: int) -> tuple[JobEvent, ...]:
        with self.authority.connect() as connection:
            self.read(connection, identifier)
            last = connection.execute(
                "SELECT MAX(sequence) FROM job_events WHERE job_id=?", (identifier,)
            ).fetchone()[0]
            if after < 0 or after > last:
                raise JobError(409, "invalid_event_cursor")
            rows = connection.execute(
                "SELECT sequence, payload FROM job_events WHERE job_id=? AND sequence>? "
                "ORDER BY sequence LIMIT 100",
                (identifier, after),
            ).fetchall()
        events = tuple(
            JobEvent(
                sequence=row[0],
                job=JobView.model_validate_json(canonical_bytes(parse_json(row[1]))),
            )
            for row in rows
        )
        if any(event.job.id != identifier for event in events):
            raise ValueError("event_integrity_failure")
        return events
