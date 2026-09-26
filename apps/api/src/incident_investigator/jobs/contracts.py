from typing import Annotated, Literal

from pydantic import Field, StringConstraints

from incident_investigator.evaluation.golden import IncidentInput
from incident_investigator.evaluation.models import Contract, Digest
from incident_investigator.workflow.contracts import RunPin, Stage

JobId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
Status = Literal["queued", "running", "succeeded", "failed", "cancelled"]
Reason = Literal["operator_request", "invalidated_evidence", "defective_runtime", "security_review"]
Failure = Literal["cancelled", "restricted", "incompatible_runtime", "execution_failed"]
TERMINAL = frozenset({"succeeded", "failed", "cancelled"})


class SubmitJob(Contract):
    idempotency_key: JobId
    incident: IncidentInput
    round_limit: Annotated[int, Field(ge=0, le=2)] = 2


class ReplayJob(Contract):
    idempotency_key: JobId
    mode: Literal["candidate"] = "candidate"


class RecallReport(Contract):
    reason: Reason


class JobView(Contract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    id: JobId
    status: Status = "queued"
    pin: RunPin
    input_digest: Digest
    revision: Annotated[int, Field(ge=1)] = 1
    created_at: Annotated[int, Field(ge=0)]
    updated_at: Annotated[int, Field(ge=0)]
    stage: Stage = "scope"
    completed_steps: Annotated[int, Field(ge=0, le=20)] = 0
    failure: Failure | None = None
    replay_of: JobId | None = None
    report_status: Literal["none", "available", "recalled", "superseded"] = "none"
    recall_reason: Reason | None = None
    replacement_id: JobId | None = None


class JobEvent(Contract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    sequence: Annotated[int, Field(ge=1)]
    job: JobView


class JobError(Exception):
    def __init__(self, status: int, code: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
