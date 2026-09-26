"""Append-only JSON checkpoints at serial node boundaries, never pickle snapshots.

An interrupted evidence fan-out is replayed from the preceding boundary. These
checkpoints do not serialize LangGraph tasks, Python objects or partial writes.
"""

import sqlite3
from collections.abc import Callable

from incident_investigator.evaluation.canonical import (
    MAX_BYTES,
    canonical_bytes,
    content_digest,
    parse_json,
)
from incident_investigator.security.authority import AuditEvent, SecurityAuthority
from incident_investigator.security.policy import (
    ActionRequest,
    OperationDenied,
    SecurityContext,
    SecurityPolicy,
    authorize,
)
from incident_investigator.workflow.contracts import RunState
from incident_investigator.workflow.graph import decode, make_report, validate_state

CheckpointGuard = Callable[[sqlite3.Connection, RunState], None]


def state_digest(state: RunState) -> str:
    return content_digest(parse_json(state.model_dump_json()))


class CheckpointStore:
    def __init__(self, authority: SecurityAuthority) -> None:
        self.authority = authority
        with authority.connect() as connection:
            connection.executescript(
                "CREATE TABLE IF NOT EXISTS workflow_attempts ("
                "attempt_id TEXT PRIMARY KEY, head_digest TEXT NOT NULL, policy BLOB NOT NULL);"
                "CREATE TABLE IF NOT EXISTS workflow_checkpoints ("
                "attempt_id TEXT NOT NULL, step INTEGER NOT NULL, digest TEXT NOT NULL, "
                "previous_digest TEXT, payload BLOB NOT NULL CHECK(length(payload)<=1048576), "
                "PRIMARY KEY(attempt_id, step));"
            )

    def load(self, attempt_id: str) -> tuple[RunState, SecurityPolicy]:
        with self.authority.connect() as connection:
            row = connection.execute(
                "SELECT c.payload, c.digest, a.policy FROM workflow_attempts a "
                "JOIN workflow_checkpoints c ON c.attempt_id=a.attempt_id "
                "AND c.digest=a.head_digest "
                "WHERE a.attempt_id=?",
                (attempt_id,),
            ).fetchone()
        if row is None:
            raise ValueError("attempt_unavailable")
        if len(row[0]) > MAX_BYTES or len(row[2]) > MAX_BYTES:
            raise ValueError("checkpoint_too_large")
        state = RunState.model_validate_json(canonical_bytes(parse_json(row[0])))
        policy = SecurityPolicy.model_validate_json(canonical_bytes(parse_json(row[2])))
        if state.attempt_id != attempt_id or state_digest(state) != row[1]:
            raise ValueError("checkpoint_integrity_failure")
        if state.pin.policy_digest != content_digest(parse_json(policy.model_dump_json())):
            raise ValueError("checkpoint_policy_mismatch")
        validate_state(state, state.pin)
        if state.next_stage == "done" and state.report != make_report(state):
            raise ValueError("checkpoint_report_mismatch")
        return state, policy

    def save(
        self,
        state: RunState,
        policy: SecurityPolicy,
        *,
        expected: RunState | None,
        now: int,
        guard: CheckpointGuard | None = None,
    ) -> None:
        state = decode(state.model_dump(mode="json"))
        validate_state(state, state.pin)
        if state.pin.policy_digest != content_digest(parse_json(policy.model_dump_json())):
            raise ValueError("checkpoint_policy_mismatch")
        digest = state_digest(state)
        payload = canonical_bytes(parse_json(state.model_dump_json()))
        with self.authority.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if guard is not None:
                guard(connection, state)
            if expected is None:
                if state.completed or state.next_stage != "scope" or state.report is not None:
                    raise ValueError("initial_checkpoint_required")
                if connection.execute(
                    "SELECT 1 FROM workflow_attempts WHERE attempt_id=?", (state.attempt_id,)
                ).fetchone():
                    raise ValueError("attempt_already_exists")
            else:
                previous = state_digest(expected)
                current = connection.execute(
                    "SELECT head_digest FROM workflow_attempts WHERE attempt_id=?",
                    (state.attempt_id,),
                ).fetchone()
                if current is None or current[0] != previous:
                    raise ValueError("checkpoint_conflict")
                if (state.attempt_id, state.pin, state.input_digest, state.round_limit) != (
                    expected.attempt_id,
                    expected.pin,
                    expected.input_digest,
                    expected.round_limit,
                ):
                    raise ValueError("checkpoint_pin_mismatch")
                if state.completed != (*expected.completed, expected.next_stage):
                    raise ValueError("checkpoint_sequence_mismatch")
            context = SecurityContext(
                actor_id="local-operator",
                candidate_id=state.pin.candidate_id,
                policy_id=policy.id,
                account_id=state.incident.account_id,
                region=state.incident.region,
            )
            request = ActionRequest(
                operation="report.publish" if state.report is not None else "fixture.read",
                account_id=context.account_id,
                region=context.region,
                resource=state.incident.resource,
                template="offline-investigation-v1",
                result_limit=max(1, len(state.incident.observations)),
                cost_microdollars=0,
            )
            # The SQLite writer lock prevents concurrent restriction updates from
            # committing between this read and the checkpoint/audit commit.
            decision = authorize(
                context, request, policy, self.authority.current_policy(policy), now
            )
            if not decision.allowed:
                raise OperationDenied(decision.reason)
            self.authority._append(
                connection,
                AuditEvent(
                    actor_id=context.actor_id,
                    action="workflow.checkpoint",
                    decision="allow",
                    reason="validated_boundary",
                    policy_revision=decision.policy_revision,
                    artifact_ids=(state.attempt_id, state.pin.candidate_id),
                ),
            )
            connection.execute(
                "INSERT INTO workflow_checkpoints VALUES (?, ?, ?, ?, ?)",
                (
                    state.attempt_id,
                    len(state.completed),
                    digest,
                    state_digest(expected) if expected is not None else None,
                    payload,
                ),
            )
            if expected is None:
                connection.execute(
                    "INSERT INTO workflow_attempts VALUES (?, ?, ?)",
                    (state.attempt_id, digest, policy.model_dump_json().encode()),
                )
            else:
                connection.execute(
                    "UPDATE workflow_attempts SET head_digest=? WHERE attempt_id=?",
                    (digest, state.attempt_id),
                )
