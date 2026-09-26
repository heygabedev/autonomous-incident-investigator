from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from incident_investigator.evaluation.models import Contract, Digest, Identifier, Text, Timestamp
from incident_investigator.security.evidence import SanitizedEvidence, evidence_bytes, redact

Modality = Literal["log", "metric", "trace", "change"]
Stage = Literal[
    "scope",
    "collect",
    "correlate",
    "hypothesize",
    "verify",
    "request",
    "history",
    "plan",
    "report",
    "done",
]
Cause = Literal[
    "missing_required_environment_variable",
    "dynamodb_write_throttling",
    "target_group_port_mismatch",
    "execution_role_permission_removed",
]
Signal = Literal[
    "env_removed",
    "startup_missing_env",
    "target_health_loss",
    "write_capacity_exhausted",
    "putitem_throttled",
    "throughput_exceeded",
    "port_mismatch",
    "listener_ready",
    "health_probe_failure",
    "getitem_permission_removed",
    "getitem_denied",
    "getitem_failure_no_throttle",
    "errors_without_detail",
    "startup_healthy",
]


class Observation(Contract):
    source_id: Identifier
    modality: Modality
    provenance_group: Identifier
    occurred_at: Timestamp
    observed_at: Timestamp
    signal: Signal
    cohort: Identifier | None = None
    available_round: Annotated[int, Field(ge=0, le=2)] = 0
    evidence: SanitizedEvidence


class CoverageGap(Contract):
    source_id: Identifier
    modality: Modality
    reason: Literal["permission_denied", "unavailable", "unsupported_payload"]


class ReplayInput(Contract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    source: Literal["synthetic"] = "synthetic"
    case_id: Identifier
    workload: Literal["ecs_fargate", "lambda_serverless"]
    account_id: Literal["000000000000"]
    region: Literal["eu-central-1"]
    resource: Identifier
    window_start: Timestamp
    window_end: Timestamp
    investigation_cutoff: Timestamp
    observations: Annotated[tuple[Observation, ...], Field(max_length=100)]
    gaps: Annotated[tuple[CoverageGap, ...], Field(max_length=100)]

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        if not self.window_start <= self.window_end <= self.investigation_cutoff:
            raise ValueError("invalid_window")
        source_ids = [item.source_id for item in self.observations] + [
            item.source_id for item in self.gaps
        ]
        if len(source_ids) > 100 or len(source_ids) != len(set(source_ids)):
            raise ValueError("duplicate_or_excessive_source_ids")
        for item in self.observations:
            if not self.window_start <= item.occurred_at <= self.window_end:
                raise ValueError("evidence_outside_window")
            if not item.occurred_at <= item.observed_at <= self.investigation_cutoff:
                raise ValueError("evidence_after_cutoff")
            fields = {field.name: field.value for field in item.evidence.fields}
            expected = {"status": item.signal, "operation": f"{item.modality}.{item.source_id}"}
            if item.cohort is not None:
                expected["value"] = item.cohort
            if fields != expected:
                raise ValueError("signal_evidence_mismatch")
        evidence_bytes(
            tuple(item.evidence for item in self.observations),
            self.account_id,
            self.region,
            (self.resource,),
        )
        # Metadata is untrusted too; do not let a source identifier bypass redaction.
        metadata = (
            self.case_id,
            self.resource,
            *source_ids,
            *(item.provenance_group for item in self.observations),
        )
        if any(redact(value) != value for value in metadata):
            raise ValueError("unsafe_metadata")
        return self


class RunPin(Contract):
    """Offline identity, not an approved deployable ReleaseBundle."""

    release_id: Identifier
    candidate_id: Identifier
    candidate_digest: Digest
    graph_digest: Digest
    policy_digest: Digest
    graph_version: Literal["1.0.0"] = "1.0.0"
    state_version: Literal["1.0.0"] = "1.0.0"
    report_version: Literal["1.0.0"] = "1.0.0"
    mode: Literal["fixture"] = "fixture"


class Hypothesis(Contract):
    cause: Cause
    evidence_ids: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=100)]
    verdict: Literal["pending", "supported", "insufficient", "contradicted"] = "pending"


class Recommendation(Contract):
    cause: Cause
    instruction: Text
    prerequisites: Text
    risk: Text
    rollback: Text
    validation: Text
    evidence_ids: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=100)]
    execution: Literal["operator_only"] = "operator_only"
    source: Literal["reviewed_template"] = "reviewed_template"


class InvestigationReport(Contract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    attempt_id: Identifier
    pin: RunPin
    status: Literal["resolved", "degraded", "unresolved"]
    hypotheses: Annotated[tuple[Hypothesis, ...], Field(max_length=4)]
    recommendations: Annotated[tuple[Recommendation, ...], Field(max_length=3)]
    gaps: Annotated[tuple[CoverageGap, ...], Field(max_length=100)]
    evidence_ids: Annotated[tuple[Identifier, ...], Field(max_length=100)]
    history_status: Literal["disabled"] = "disabled"
    confidence: Literal["uncalibrated_fixture_rules"] = "uncalibrated_fixture_rules"
    model_calls: Literal[0] = 0
    cost_microdollars: Literal[0] = 0


class RunState(Contract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    attempt_id: Identifier
    pin: RunPin
    input_digest: Digest
    incident: ReplayInput
    next_stage: Stage = "scope"
    completed: Annotated[tuple[Stage, ...], Field(max_length=20)] = ()
    collected: Annotated[tuple[Modality, ...], Field(max_length=4)] = ()
    visible_ids: Annotated[tuple[Identifier, ...], Field(max_length=100)] = ()
    timeline: Annotated[tuple[Identifier, ...], Field(max_length=100)] = ()
    hypotheses: Annotated[tuple[Hypothesis, ...], Field(max_length=4)] = ()
    evidence_rounds: Annotated[int, Field(ge=0, le=2)] = 0
    round_limit: Annotated[int, Field(ge=0, le=2)] = 2
    history_status: Literal["not_checked", "disabled"] = "not_checked"
    recommendations: Annotated[tuple[Recommendation, ...], Field(max_length=3)] = ()
    report: InvestigationReport | None = None
