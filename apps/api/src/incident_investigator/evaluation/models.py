"""Immutable evaluation metadata. Sensitive content lives in separately scoped blobs."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
Identifier = Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")]
Version = Annotated[str, StringConstraints(pattern=r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")]
Count = Annotated[int, Field(ge=0, le=(1 << 53) - 1)]
PositiveCount = Annotated[int, Field(gt=0, le=(1 << 53) - 1)]
Probability = Annotated[int, Field(ge=0, le=1_000_000)]
Text = Annotated[str, StringConstraints(min_length=1, max_length=4096)]


def _timestamp(value: str) -> str:
    datetime.fromisoformat(value)
    return value


Timestamp = Annotated[
    str,
    StringConstraints(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"),
    AfterValidator(_timestamp),
]
Kind = Literal[
    "case_revision",
    "dataset_snapshot",
    "candidate_bundle",
    "eval_suite",
    "calibration_artifact",
    "eval_run",
    "promotion_decision",
    "release_bundle",
    "invalidation",
    "exposure",
]
Split = Literal["dev", "calibration", "sealed_test", "shadow", "core_regression"]
PermittedUse = Literal[
    "runtime_memory",
    "development",
    "calibration",
    "sealed_benchmark",
    "shadow",
    "regression",
    "public_release",
]


class Contract(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True, validate_default=True)


class ArtifactRef(Contract):
    kind: Kind
    id: Identifier
    version: Version
    digest: Digest


class Component(Contract):
    name: Identifier
    version: Version
    digest: Digest


class Entity(Contract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    id: Identifier
    version: Version
    created_at: Timestamp
    parents: tuple[ArtifactRef, ...] = ()


class CandidateInput(Contract):
    """The runner receives only this input projection, never a CaseRevision."""

    case_id: Identifier
    input_digest: Digest
    investigation_cutoff: Timestamp


class GoldLabels(Contract):
    case_id: Identifier
    labels_digest: Digest
    labeling_policy: Component


class CaseRevision(Entity):
    kind: Literal["case_revision"] = "case_revision"
    candidate_input: CandidateInput
    gold_labels: GoldLabels
    source: Literal["synthetic", "sanitized_real"]
    provenance_digest: Digest
    lineage_id: Identifier
    duplicate_cluster_id: Identifier
    lifecycle: Literal["pending", "verified", "superseded", "revoked"]
    data_stage: Literal[
        "quarantined", "sanitized", "labeled", "owner_reviewed", "shadow", "eligible", "frozen"
    ]
    permitted_uses: tuple[PermittedUse, ...]
    owner_approval_digest: Digest | None = None

    @model_validator(mode="after")
    def check_identity_and_approval(self) -> Self:
        if self.candidate_input.case_id != self.id or self.gold_labels.case_id != self.id:
            raise ValueError("case input and label identities must match")
        if len(set(self.permitted_uses)) != len(self.permitted_uses):
            raise ValueError("duplicate permitted use")
        if (
            self.source == "sanitized_real"
            and self.permitted_uses
            and not self.owner_approval_digest
        ):
            raise ValueError("real-case eligibility requires an owner approval reference")
        if self.lifecycle in ("revoked", "superseded") and self.permitted_uses:
            raise ValueError("withdrawn cases cannot grant permitted uses")
        return self


class DatasetMember(Contract):
    case: ArtifactRef
    split: Split

    @model_validator(mode="after")
    def check_case_kind(self) -> Self:
        if self.case.kind != "case_revision":
            raise ValueError("dataset members must reference case revisions")
        return self


class SliceCount(Contract):
    name: Identifier
    count: Count


class DatasetSnapshot(Entity):
    kind: Literal["dataset_snapshot"] = "dataset_snapshot"
    members: Annotated[tuple[DatasetMember, ...], Field(min_length=1)]
    memory_snapshot_digest: Digest
    governance_digest: Digest
    sanitizer: Component
    labeling_policy: Component
    split_policy: Component
    slice_counts: tuple[SliceCount, ...] = ()

    @model_validator(mode="after")
    def check_unique_members(self) -> Self:
        if len({m.case.id for m in self.members}) != len(self.members):
            raise ValueError("a case may appear only once per snapshot")
        if len({s.name for s in self.slice_counts}) != len(self.slice_counts):
            raise ValueError("duplicate slice count")
        return self


class ModelConfiguration(Contract):
    provider: Literal["fixture", "bedrock"]
    model_id: Text
    region: Identifier
    adapter: Component
    settings_digest: Digest
    inference_destinations: Annotated[tuple[Identifier, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def check_single_region(self) -> Self:
        if self.inference_destinations != (self.region,):
            raise ValueError("v1 inference must remain in the configured Region")
        return self


class EmbeddingConfiguration(Contract):
    model_id: Text
    dimensions: PositiveCount
    normalization: Literal["none", "l2"]
    document_template_digest: Digest


class RetrievalConfiguration(Contract):
    memory_snapshot_digest: Digest
    index_generation: Identifier
    embedding: EmbeddingConfiguration
    fusion: Component
    reranker: Component
    feature_schema: Component


class Budgets(Contract):
    model_calls: Annotated[int, Field(ge=1, le=8)]
    input_tokens: Annotated[int, Field(ge=1, le=80_000)]
    output_tokens: Annotated[int, Field(ge=1, le=12_000)]
    evidence_rounds: Annotated[int, Field(ge=0, le=2)]
    embedding_calls: PositiveCount
    embedding_input_tokens: PositiveCount
    estimated_cost_microdollars: Annotated[int, Field(ge=1, le=500_000)]
    rate_card: Component


class CandidateBundle(Entity):
    kind: Literal["candidate_bundle"] = "candidate_bundle"
    code_sha: Annotated[str, StringConstraints(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")]
    source_artifact_digest: Digest
    dependency_locks: Annotated[tuple[Component, ...], Field(min_length=1)]
    prompts: Annotated[tuple[Component, ...], Field(min_length=1)]
    graph: Component
    state_schema: Component
    report_schema: Component
    authorization_policy: Component
    admission_policy: Component
    redaction: Component
    model: ModelConfiguration
    retrieval: RetrievalConfiguration
    calibration: ArtifactRef | None
    historical_actions_enabled: bool
    cause_threshold_ppm: Annotated[int, Field(ge=900_000, le=1_000_000)]
    applicability_threshold_ppm: Annotated[int, Field(ge=900_000, le=1_000_000)]
    budgets: Budgets

    @model_validator(mode="after")
    def check_components(self) -> Self:
        for components in (self.prompts, self.dependency_locks):
            if len({c.name for c in components}) != len(components):
                raise ValueError("duplicate component name")
        if self.historical_actions_enabled and self.calibration is None:
            raise ValueError("historical inclusion requires calibration")
        if self.calibration is not None and self.calibration.kind != "calibration_artifact":
            raise ValueError("invalid calibration reference kind")
        return self


class MetricGate(Contract):
    name: Identifier
    scorer: Component
    direction: Literal["higher", "lower"]
    threshold_decimal: Annotated[str, StringConstraints(pattern=r"^-?(0|[1-9]\d*)(\.\d+)?$")]
    non_inferiority_margin_decimal: Annotated[
        str, StringConstraints(pattern=r"^(0|[1-9]\d*)(\.\d+)?$")
    ]
    denominator: Identifier
    independent_unit: Literal["base_incident", "lineage_cluster"]
    minimum_independent_samples: PositiveCount
    slices: Annotated[tuple[SliceCount, ...], Field(min_length=1)]
    missing_output_policy: Literal["fail", "insufficient_evidence"]
    statistical_procedure: Component

    @model_validator(mode="after")
    def check_slice_minima(self) -> Self:
        if any(s.count == 0 for s in self.slices):
            raise ValueError("gate slices require positive sample minima")
        if len({s.name for s in self.slices}) != len(self.slices):
            raise ValueError("duplicate gate slice")
        return self


class EvalSuite(Entity):
    kind: Literal["eval_suite"] = "eval_suite"
    name: Literal[
        "pr-smoke", "nightly-offline", "candidate-live", "private-release", "shadow", "drift"
    ]
    datasets: Annotated[tuple[ArtifactRef, ...], Field(min_length=1)]
    harness: Component
    repetitions: PositiveCount
    gates: Annotated[tuple[MetricGate, ...], Field(min_length=1)]
    max_sealed_submissions: PositiveCount
    exposure_policy: Component
    multiple_testing_policy: Component

    @model_validator(mode="after")
    def check_suite(self) -> Self:
        if any(ref.kind != "dataset_snapshot" for ref in self.datasets):
            raise ValueError("suite datasets must reference snapshots")
        if self.name in ("candidate-live", "private-release") and self.repetitions < 3:
            raise ValueError("live promotion evaluation requires at least three repetitions")
        if len({g.name for g in self.gates}) != len(self.gates):
            raise ValueError("duplicate metric gate")
        return self


class CalibrationArtifact(Entity):
    kind: Literal["calibration_artifact"] = "calibration_artifact"
    retrieval_fingerprint: Digest
    feature_schema: Component
    training_snapshot: ArtifactRef
    training_split: Literal["calibration"]
    parameters_digest: Digest
    validation_results_digest: Digest
    cause_threshold_ppm: Probability
    applicability_threshold_ppm: Probability

    @model_validator(mode="after")
    def check_training_kind(self) -> Self:
        if self.training_snapshot.kind != "dataset_snapshot":
            raise ValueError("calibration training must reference a dataset snapshot")
        return self


class EvalRun(Entity):
    kind: Literal["eval_run"] = "eval_run"
    candidate: ArtifactRef
    dataset: ArtifactRef
    suite: ArtifactRef
    environment_digest: Digest
    memory_snapshot_digest: Digest
    governance_digest: Digest
    trajectories_digest: Digest
    results_digest: Digest
    status: Literal["passed", "failed", "insufficient_evidence"]
    repetitions: PositiveCount
    model_calls: Count
    input_tokens: Count
    output_tokens: Count
    cost_microdollars: Count
    latency_ms: Count

    @model_validator(mode="after")
    def check_run_refs(self) -> Self:
        if (self.candidate.kind, self.dataset.kind, self.suite.kind) != (
            "candidate_bundle",
            "dataset_snapshot",
            "eval_suite",
        ):
            raise ValueError("invalid run reference kinds")
        return self


class PromotionDecision(Entity):
    kind: Literal["promotion_decision"] = "promotion_decision"
    champion: ArtifactRef
    challenger: ArtifactRef
    qualifying_runs: Annotated[tuple[ArtifactRef, ...], Field(min_length=1)]
    comparison_digest: Digest
    reviewer: Identifier
    decision: Literal["approved", "rejected", "insufficient_evidence"]
    rollback_target: ArtifactRef

    @model_validator(mode="after")
    def check_decision_refs(self) -> Self:
        if self.champion.kind != "candidate_bundle" or self.challenger.kind != "candidate_bundle":
            raise ValueError("promotion compares candidate bundles")
        if any(ref.kind != "eval_run" for ref in self.qualifying_runs):
            raise ValueError("qualifying evidence must reference evaluation runs")
        if self.rollback_target.kind != "release_bundle":
            raise ValueError("rollback target must reference a release")
        return self


class Compatibility(Contract):
    name: Literal["api", "sse", "report", "event", "database", "checkpoint"]
    supported_versions: Annotated[tuple[Version, ...], Field(min_length=1)]


class ReleaseBundle(Entity):
    kind: Literal["release_bundle"] = "release_bundle"
    candidate: ArtifactRef
    evaluation_run: ArtifactRef
    approval: ArtifactRef
    application_artifacts: Annotated[tuple[Component, ...], Field(min_length=3)]
    compatibility: Annotated[tuple[Compatibility, ...], Field(min_length=6, max_length=6)]
    terraform: Component
    infrastructure_prerequisites_digest: Digest
    previous_known_good: ArtifactRef | None

    @model_validator(mode="after")
    def check_release_refs(self) -> Self:
        if (self.candidate.kind, self.evaluation_run.kind, self.approval.kind) != (
            "candidate_bundle",
            "eval_run",
            "promotion_decision",
        ):
            raise ValueError("invalid release reference kinds")
        if (
            self.previous_known_good is not None
            and self.previous_known_good.kind != "release_bundle"
        ):
            raise ValueError("previous known good must reference a release")
        names = [a.name for a in self.application_artifacts]
        if not {"api", "worker", "ui"}.issubset(names) or len(names) != len(set(names)):
            raise ValueError("release requires distinct api, worker, and ui artifacts")
        if len({c.name for c in self.compatibility}) != 6:
            raise ValueError("release requires all six compatibility contracts")
        return self


class Invalidation(Entity):
    kind: Literal["invalidation"] = "invalidation"
    target: ArtifactRef
    actor: Identifier
    reason_code: Identifier
    evidence_digest: Digest


class Exposure(Entity):
    kind: Literal["exposure"] = "exposure"
    dataset: ArtifactRef
    candidate: ArtifactRef
    actor: Identifier
    disclosure: Literal["submission", "aggregate", "row_level", "development_use"]
    case_ids: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def check_exposure(self) -> Self:
        if self.dataset.kind != "dataset_snapshot" or self.candidate.kind != "candidate_bundle":
            raise ValueError("invalid exposure references")
        if self.disclosure in ("row_level", "development_use") and not self.case_ids:
            raise ValueError("row-level exposure must identify the disclosed cases")
        if len(set(self.case_ids)) != len(self.case_ids):
            raise ValueError("duplicate exposed case")
        return self


Artifact = Annotated[
    CaseRevision
    | DatasetSnapshot
    | CandidateBundle
    | EvalSuite
    | CalibrationArtifact
    | EvalRun
    | PromotionDecision
    | ReleaseBundle
    | Invalidation
    | Exposure,
    Field(discriminator="kind"),
]
