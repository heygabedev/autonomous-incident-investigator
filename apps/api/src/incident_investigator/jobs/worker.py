"""One local worker, with database leases and checkpoint-level fencing across processes."""

import sqlite3
import threading
import uuid

from incident_investigator.jobs.contracts import Failure, JobError, JobView
from incident_investigator.jobs.store import JobStore
from incident_investigator.security.policy import OperationDenied
from incident_investigator.workflow.contracts import RunState
from incident_investigator.workflow.runtime import OfflineRuntime, offline_pin

LEASE_SECONDS = 30


class Worker:
    def __init__(self, store: JobStore) -> None:
        self.store = store
        self.stopping = threading.Event()
        self.thread: threading.Thread | None = None

    def claim(self) -> tuple[JobView, str] | None:
        with self.store.authority.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if self.store.authority.read().safe_mode:
                return None
            rows = connection.execute(
                "SELECT id FROM jobs WHERE json_extract(view, '$.status')='queued' "
                "OR (json_extract(view, '$.status')='running' AND lease_until<=?) "
                "ORDER BY rowid LIMIT 32",
                (self.store.clock(),),
            ).fetchall()
            for row in rows:
                job = self.store.read(connection, row[0])
                if job.dispatch_attempts >= 3:
                    job = self.store.changed(job, status="failed", failure="execution_failed")
                    self.store.audit(connection, "local-worker", "job.exhausted", job)
                    self.store.write(connection, job)
                    continue
                token = uuid.uuid4().hex
                job = self.store.changed(
                    job, status="running", dispatch_attempts=job.dispatch_attempts + 1
                )
                self.store.audit(connection, "local-worker", "job.claim", job)
                self.store.write(connection, job)
                connection.execute(
                    "UPDATE jobs SET lease_token=?, lease_until=? WHERE id=?",
                    (token, self.store.clock() + LEASE_SECONDS, job.id),
                )
                return job, token
        return None

    def guard(
        self, identifier: str, token: str, connection: sqlite3.Connection, state: RunState
    ) -> None:
        job = self.store.read(connection, identifier)
        lease = connection.execute(
            "SELECT lease_token, lease_until FROM jobs WHERE id=?", (identifier,)
        ).fetchone()
        if self.stopping.is_set():
            raise JobError(409, "worker_stopping")
        if job.status != "running" or lease[0] != token or lease[1] <= self.store.clock():
            raise JobError(409, "lease_lost")
        if self.store.authority.read().safe_mode:
            raise OperationDenied("contained")
        self.store.check_lineage(connection, job)
        if (state.attempt_id, state.pin, state.input_digest) != (job.id, job.pin, job.input_digest):
            raise ValueError("job_checkpoint_mismatch")
        completed = state.next_stage == "done"
        job = self.store.changed(
            job,
            stage=state.next_stage,
            completed_steps=len(state.completed),
            status="succeeded" if completed else "running",
            report_status="available" if completed else "none",
        )
        self.store.audit(connection, "local-worker", "job.progress", job)
        self.store.write(connection, job)
        connection.execute(
            "UPDATE jobs SET lease_until=?, lease_token=? WHERE id=?",
            (
                0 if completed else self.store.clock() + LEASE_SECONDS,
                None if completed else token,
                job.id,
            ),
        )
        if completed and job.replay_of is not None:
            parent = self.store.read(connection, job.replay_of)
            # Only an explicit recall is eligible for automatic supersession.
            if parent.report_status == "recalled":
                parent = self.store.changed(
                    parent, report_status="superseded", replacement_id=job.id
                )
                self.store.audit(connection, "local-worker", "report.supersede", parent)
                self.store.write(connection, parent)

    def failure(self, identifier: str, token: str, reason: Failure) -> None:
        with self.store.authority.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            job = self.store.read(connection, identifier)
            lease = connection.execute(
                "SELECT lease_token FROM jobs WHERE id=?", (identifier,)
            ).fetchone()
            if job.status != "running" or lease[0] != token:
                return
            job = self.store.changed(job, status="failed", failure=reason)
            self.store.audit(connection, "local-worker", "job.fail", job)
            self.store.write(connection, job)
            connection.execute(
                "UPDATE jobs SET lease_token=NULL, lease_until=0 WHERE id=?", (identifier,)
            )

    def process(self, job: JobView, token: str) -> None:
        def fence(connection: sqlite3.Connection, state: RunState) -> None:
            self.guard(job.id, token, connection, state)

        try:
            runtime = OfflineRuntime(self.store.authority, self.store.clock, fence)
            initial, policy = self.store.initial(job.id)
            if initial.pin != offline_pin(policy):
                self.failure(job.id, token, "incompatible_runtime")
                return
            with self.store.authority.connect() as connection:
                exists = connection.execute(
                    "SELECT 1 FROM workflow_attempts WHERE attempt_id=?", (job.id,)
                ).fetchone()
            if exists:
                runtime.resume(job.id)
            else:
                runtime.begin(initial, policy)
        except JobError as exc:
            if exc.code not in ("worker_stopping", "lease_lost"):
                self.failure(job.id, token, "execution_failed")
        except OperationDenied:
            self.failure(job.id, token, "restricted")
        except Exception:
            # Never persist exception text, stack traces, telemetry or submitted data.
            self.failure(job.id, token, "execution_failed")

    def run_once(self) -> bool:
        claimed = self.claim()
        if claimed is None:
            return False
        self.process(*claimed)
        return True

    def start(self) -> None:
        if self.thread is not None:
            raise RuntimeError("worker_already_started")

        def loop() -> None:
            while not self.stopping.is_set():
                try:
                    worked = self.run_once()
                except Exception:
                    # Storage/audit failure stops dispatch. Health and local containment survive.
                    worked = False
                if not worked:
                    self.stopping.wait(0.25)

        self.thread = threading.Thread(target=loop, name="fixture-worker", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stopping.set()
        if self.thread is not None:
            self.thread.join(timeout=5)
