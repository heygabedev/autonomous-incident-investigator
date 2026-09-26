import uuid

from incident_investigator.evaluation.canonical import canonical_bytes, content_digest, parse_json
from incident_investigator.jobs.contracts import (
    TERMINAL,
    JobError,
    JobView,
    Reason,
    ReplayJob,
    SubmitJob,
)
from incident_investigator.jobs.store import JobStore
from incident_investigator.security.evidence import evidence_bytes
from incident_investigator.security.policy import (
    ActionRequest,
    OperationDenied,
    SecurityContext,
    authorize,
)
from incident_investigator.workflow.graph import make_report
from incident_investigator.workflow.replay import prepare
from incident_investigator.workflow.runtime import OfflineRuntime


class JobService:
    def __init__(self, store: JobStore) -> None:
        self.store = store
        self.runtime = OfflineRuntime(store.authority, store.clock)

    def submit(self, request: SubmitJob, actor: str) -> JobView:
        # Raw free text is transient: preparation precedes every persistent write.
        ready = prepare(request.incident)
        fingerprint = content_digest(
            parse_json(request.model_dump_json(exclude={"idempotency_key"}))
        )
        state, policy = self.runtime.initialize(ready, round_limit=request.round_limit)
        return self.store.submit(state, policy, request.idempotency_key, fingerprint, actor)

    def replay(self, identifier: str, request: ReplayJob, actor: str) -> JobView:
        original, _ = self.store.initial(identifier)
        state, policy = self.runtime.initialize(
            original.incident, uuid.uuid4().hex, original.round_limit
        )
        fingerprint = content_digest({"replay_of": identifier, "mode": request.mode})
        return self.store.submit(
            state, policy, request.idempotency_key, fingerprint, actor, replay_of=identifier
        )

    def cancel(self, identifier: str, actor: str) -> JobView:
        with self.store.authority.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            job = self.store.read(connection, identifier)
            if job.status == "cancelled":
                return job
            if job.status in TERMINAL:
                raise JobError(409, "job_already_terminal")
            job = self.store.changed(job, status="cancelled", failure="cancelled")
            self.store.audit(connection, actor, "job.cancel", job)
            self.store.write(connection, job)
            connection.execute(
                "UPDATE jobs SET lease_token=NULL, lease_until=0 WHERE id=?", (job.id,)
            )
        return job

    def recall(self, identifier: str, reason: Reason, actor: str) -> JobView:
        with self.store.authority.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            job = self.store.read(connection, identifier)
            if job.report_status in ("recalled", "superseded"):
                return job
            if job.report_status != "available":
                raise JobError(409, "report_unavailable")
            job = self.store.changed(job, report_status="recalled", recall_reason=reason)
            self.store.audit(connection, actor, "report.recall", job)
            self.store.write(connection, job)
        return job

    def deliver(self, identifier: str, actor: str, *, evidence: bool = False) -> bytes:
        # Recall, revocation and publication are serialized at the delivery boundary.
        # Already delivered bytes cannot be revoked from a client or its OS account.
        with self.store.authority.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            job = self.store.read(connection, identifier)
            if not evidence and (job.status != "succeeded" or job.report_status != "available"):
                raise JobError(409, "report_unavailable")
            state, policy = (
                self.store.initial(identifier) if evidence else self.runtime.store.load(identifier)
            )
            if state.pin != job.pin or state.input_digest != job.input_digest:
                raise ValueError("job_checkpoint_mismatch")
            context = SecurityContext(
                actor_id=actor,
                candidate_id=job.pin.candidate_id,
                policy_id=policy.id,
                account_id=state.incident.account_id,
                region=state.incident.region,
            )
            request = ActionRequest(
                operation="fixture.read" if evidence else "report.publish",
                account_id=context.account_id,
                region=context.region,
                resource=state.incident.resource,
                template="offline-investigation-v1",
                result_limit=100,
                cost_microdollars=0,
            )
            decision = authorize(
                context,
                request,
                policy,
                self.store.authority.current_policy(policy),
                self.store.clock(),
            )
            if not decision.allowed:
                raise OperationDenied(decision.reason)
            self.store.audit(
                connection, actor, "evidence.export" if evidence else "report.export", job
            )
            if evidence:
                return evidence_bytes(
                    tuple(item.evidence for item in state.incident.observations),
                    context.account_id,
                    context.region,
                    (state.incident.resource,),
                )
            return canonical_bytes(parse_json(make_report(state).model_dump_json()))
