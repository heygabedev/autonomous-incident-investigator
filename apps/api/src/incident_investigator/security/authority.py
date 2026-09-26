"""Current restrictions and audit share one authority, independent of release rollback.

Audit is append-only through this application's interface, not tamper-proof against
an administrator, the owning OS account, or direct edits to the SQLite database.
"""

import os
import re
import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Literal, cast

from pydantic import Field, TypeAdapter

from incident_investigator.evaluation.canonical import (
    JSONValue,
    canonical_bytes,
    content_digest,
    parse_json,
)
from incident_investigator.evaluation.models import Contract, Identifier
from incident_investigator.security.evidence import SanitizedEvidence, evidence_bytes
from incident_investigator.security.policy import (
    OPERATIONS,
    ActionRequest,
    AuthorizationDecision,
    Broker,
    Feature,
    SecurityContext,
    SecurityPolicy,
)
from incident_investigator.security.storage import (
    latch_safe_mode,
    local_path,
    private_file,
    protect_directory,
)


class Restrictions(Contract):
    revision: Annotated[int, Field(ge=1)] = 1
    safe_mode: bool = False
    disabled_features: Annotated[tuple[Feature, ...], Field(max_length=4)] = ()
    revoked_candidates: Annotated[tuple[Identifier, ...], Field(max_length=1000)] = ()


class AuditEvent(Contract):
    actor_id: Identifier
    action: Identifier
    decision: Literal["allow", "deny", "contain"]
    reason: Identifier
    policy_revision: Annotated[int, Field(ge=1)] | None
    artifact_ids: Annotated[tuple[Identifier, ...], Field(max_length=100)] = ()


class SecurityAuthority:
    def __init__(self, directory: Path) -> None:
        self.root = protect_directory(directory)
        self.path = private_file(self.root / "security.sqlite3")
        self.latch = self.root / "safe-mode"
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                "CREATE TABLE IF NOT EXISTS restrictions (id INTEGER PRIMARY KEY CHECK(id=1), "
                "payload BLOB NOT NULL);"
                "CREATE TABLE IF NOT EXISTS audit (sequence INTEGER PRIMARY KEY, "
                "created_at INTEGER NOT NULL, payload BLOB NOT NULL);"
                "CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY, payload BLOB NOT NULL);"
            )
            connection.execute(
                "INSERT OR IGNORE INTO restrictions VALUES (1, ?)",
                (Restrictions().model_dump_json().encode(),),
            )
        self._environment_latch()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        # Inspect sidecars as well: SQLite follows paths when opening WAL/journal files.
        for suffix in ("", "-wal", "-shm", "-journal"):
            local_path(Path(str(self.path) + suffix))
        connection = sqlite3.connect(self.path, timeout=2)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            with connection:
                yield connection
        finally:
            connection.close()

    def _latch(self) -> None:
        # An empty, fsynced file is enough; interrupted writes cannot clear containment.
        latch_safe_mode(self.root)

    def _environment_latch(self) -> None:
        if os.environ.get("INCIDENT_AGENT_SAFE_MODE") == "1":
            self._latch()

    @staticmethod
    def _read(connection: sqlite3.Connection) -> Restrictions:
        row = connection.execute("SELECT payload FROM restrictions WHERE id=1").fetchone()
        if row is None:
            raise ValueError("restrictions_unavailable")
        return Restrictions.model_validate_json(row[0])

    def read(self) -> Restrictions:
        self._environment_latch()
        with self.connect() as connection:
            state = self._read(connection)
        local_path(self.latch)
        return state.model_copy(update={"safe_mode": state.safe_mode or self.latch.exists()})

    @staticmethod
    def _append(connection: sqlite3.Connection, event: AuditEvent) -> None:
        event = AuditEvent.model_validate_json(event.model_dump_json())
        connection.execute(
            "INSERT INTO audit (created_at, payload) VALUES (?, ?)",
            (time.time_ns(), canonical_bytes(cast(JSONValue, event.model_dump(mode="json")))),
        )

    def record(self, event: AuditEvent) -> None:
        with self.connect() as connection:
            self._append(connection, event)

    def change(
        self,
        action: Literal["safe_enable", "safe_disable", "disable", "enable", "revoke"],
        *,
        feature: Feature | None = None,
        candidate_id: str | None = None,
    ) -> Restrictions:
        if action == "safe_disable" and os.environ.get("INCIDENT_AGENT_SAFE_MODE") == "1":
            raise ValueError("environment_containment_active")
        if action == "safe_enable":
            self._latch()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            state = self._read(connection)
            values = state.model_dump(mode="json")
            values["revision"] = state.revision + 1
            if action in ("safe_enable", "safe_disable"):
                values["safe_mode"] = action == "safe_enable"
            elif action in ("disable", "enable") and feature is not None:
                features = set(state.disabled_features)
                features.add(feature) if action == "disable" else features.discard(feature)
                values["disabled_features"] = sorted(features)
            elif action == "revoke" and candidate_id is not None:
                values["revoked_candidates"] = sorted({*state.revoked_candidates, candidate_id})
            else:
                raise ValueError("invalid_control")
            updated = Restrictions.model_validate_json(canonical_bytes(values))
            self._append(
                connection,
                AuditEvent(
                    actor_id="local-operator",
                    action=action,
                    decision="contain",
                    reason="operator_request",
                    policy_revision=updated.revision,
                ),
            )
            connection.execute(
                "UPDATE restrictions SET payload=? WHERE id=1",
                (updated.model_dump_json().encode(),),
            )
        if action == "safe_disable":
            local_path(self.latch)
            self.latch.unlink(missing_ok=True)
        return self.read()

    def current_policy(self, pinned: SecurityPolicy) -> SecurityPolicy:
        state = self.read()
        return pinned.model_copy(
            update={
                "revision": pinned.revision + state.revision,
                "safe_mode": pinned.safe_mode or state.safe_mode,
                "disabled_features": tuple(
                    sorted({*pinned.disabled_features, *state.disabled_features})
                ),
                "revoked_candidates": tuple(
                    sorted({*pinned.revoked_candidates, *state.revoked_candidates})
                ),
            }
        )

    def record_intent(
        self, context: SecurityContext, request: ActionRequest, decision: AuthorizationDecision
    ) -> None:
        # No query, resource label, model text, credentials or collector response is audited.
        self.record(
            AuditEvent(
                actor_id=context.actor_id,
                action=request.operation
                if request.operation in OPERATIONS
                else "operation.unregistered",
                decision="allow" if decision.allowed else "deny",
                reason=decision.reason,
                policy_revision=decision.policy_revision,
                artifact_ids=(context.candidate_id,),
            )
        )

    def broker(self, pinned: SecurityPolicy, clock: Callable[[], int]) -> Broker:
        return Broker(lambda: self.current_policy(pinned), self.record_intent, clock)

    def put_evidence(
        self,
        records: tuple[SanitizedEvidence, ...],
        account: str,
        region: str,
        resources: tuple[str, ...],
        actor_id: str,
    ) -> str:
        payload = evidence_bytes(records, account, region, resources)
        identifier = "artifact-" + content_digest(parse_json(payload))[7:]
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            state = self._read(connection)
            self._append(
                connection,
                AuditEvent(
                    actor_id=actor_id,
                    action="evidence.store",
                    decision="allow",
                    reason="sanitized",
                    policy_revision=state.revision,
                    artifact_ids=(identifier,),
                ),
            )
            connection.execute(
                "INSERT OR IGNORE INTO evidence VALUES (?, ?)", (identifier, payload)
            )
        return identifier

    def export_evidence(
        self,
        identifier: str,
        account: str,
        region: str,
        resources: tuple[str, ...],
        actor_id: str,
    ) -> bytes:
        if not re.fullmatch(r"artifact-[0-9a-f]{64}", identifier):
            raise ValueError("invalid_artifact_id")
        with self.connect() as connection:
            row = connection.execute(
                "SELECT payload FROM evidence WHERE id=?", (identifier,)
            ).fetchone()
            if row is None:
                raise ValueError("artifact_unavailable")
            value = parse_json(row[0])
            if identifier != "artifact-" + content_digest(value)[7:]:
                raise ValueError("artifact_integrity_failure")
            records = TypeAdapter(tuple[SanitizedEvidence, ...]).validate_json(row[0])
            payload = evidence_bytes(records, account, region, resources)
            self._append(
                connection,
                AuditEvent(
                    actor_id=actor_id,
                    action="evidence.export",
                    decision="allow",
                    reason="sanitized",
                    policy_revision=self._read(connection).revision,
                    artifact_ids=(identifier,),
                ),
            )
        return payload
