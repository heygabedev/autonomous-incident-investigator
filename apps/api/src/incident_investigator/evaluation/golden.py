"""Public development fixtures, not a sealed benchmark or a promotion gate."""

from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from incident_investigator.evaluation.canonical import (
    MAX_BYTES,
    canonical_bytes,
    content_digest,
    parse_json,
)
from incident_investigator.evaluation.models import (
    Contract,
    Digest,
    Identifier,
    Text,
    Timestamp,
    Version,
)


class FixtureEvidence(Contract):
    id: Identifier
    modality: Literal["log", "metric", "trace", "change"]
    provenance_group: Identifier
    occurred_at: Timestamp
    observed_at: Timestamp
    coverage: Literal["complete", "permission_denied", "unavailable"]
    text: Text


class IncidentInput(Contract):
    schema_version: Literal["1.0.0"]
    source: Literal["synthetic"]
    case_id: Identifier
    workload: Literal["ecs_fargate", "lambda_serverless"]
    account_id: Literal["000000000000"]
    region: Literal["eu-central-1"]
    resource: Identifier
    window_start: Timestamp
    window_end: Timestamp
    investigation_cutoff: Timestamp
    evidence: Annotated[tuple[FixtureEvidence, ...], Field(min_length=1, max_length=100)]

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        if not self.window_start <= self.window_end <= self.investigation_cutoff:
            raise ValueError("invalid investigation window")
        if len({item.id for item in self.evidence}) != len(self.evidence):
            raise ValueError("duplicate evidence ID")
        for item in self.evidence:
            if not self.window_start <= item.occurred_at <= self.window_end:
                raise ValueError("evidence outside incident window")
            if not item.occurred_at <= item.observed_at <= self.investigation_cutoff:
                raise ValueError("evidence was not available at investigation cutoff")
        return self


class ExpectedAnswer(Contract):
    schema_version: Literal["1.0.0"]
    case_id: Identifier
    expected_status: Literal["resolved", "unresolved"]
    acceptable_causes: tuple[Identifier, ...]
    required_evidence_ids: Annotated[tuple[Identifier, ...], Field(min_length=1)]
    forbidden_actions: Annotated[tuple[Identifier, ...], Field(min_length=1)]
    suggested_checks: Annotated[tuple[Text, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_answer(self) -> Self:
        if bool(self.acceptable_causes) != (self.expected_status == "resolved"):
            raise ValueError("unresolved answers must abstain from naming a cause")
        for values in (self.acceptable_causes, self.required_evidence_ids, self.forbidden_actions):
            if len(values) != len(set(values)):
                raise ValueError("duplicate expected-answer entry")
        if "execute_remediation" not in self.forbidden_actions:
            raise ValueError("all cases must prohibit remediation execution")
        return self


class GoldenMember(Contract):
    case_id: Identifier
    lineage_id: Identifier
    duplicate_cluster_id: Identifier
    split: Literal["dev"]
    input_digest: Digest
    labels_digest: Digest


class GoldenManifest(Contract):
    schema_version: Literal["1.0.0"]
    dataset_id: Literal["synthetic-golden"]
    version: Version
    source: Literal["synthetic"]
    permitted_use: Literal["development"]
    promotion_eligible: Literal[False]
    members: Annotated[tuple[GoldenMember, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_members(self) -> Self:
        if len({member.case_id for member in self.members}) != len(self.members):
            raise ValueError("duplicate dataset member")
        return self


def _load[T: Contract](path: Path, model: type[T], expected_digest: str | None = None) -> T:
    with path.open("rb") as stream:
        value = parse_json(stream.read(MAX_BYTES + 1))
    if expected_digest is not None and content_digest(value) != expected_digest:
        raise ValueError("fixture content digest mismatch")
    return model.model_validate_json(canonical_bytes(value), strict=True)


def _case_path(directory: Path, case_id: str) -> Path:
    root = directory.resolve()
    target = (root / f"{case_id}.json").resolve()
    if not target.is_relative_to(root):
        raise ValueError("fixture path escapes its directory")
    return target


def load_input(inputs_directory: Path, case_id: str, digest: str) -> IncidentInput:
    """Candidate-side loader: no label path or gold-label reference is accepted."""
    result = _load(_case_path(inputs_directory, case_id), IncidentInput, digest)
    if result.case_id != case_id:
        raise ValueError("input case identity mismatch")
    return result


def load_expected(labels_directory: Path, case_id: str, digest: str) -> ExpectedAnswer:
    """Scorer-side loader. Process isolation must enforce this boundary in private runs."""
    result = _load(_case_path(labels_directory, case_id), ExpectedAnswer, digest)
    if result.case_id != case_id:
        raise ValueError("label case identity mismatch")
    return result


def validate_golden_dataset(directory: Path) -> GoldenManifest:
    manifest = _load(directory / "manifest.json", GoldenManifest)
    seen_inputs: dict[str, tuple[str, str]] = {}
    for member in manifest.members:
        incident = load_input(directory / "inputs", member.case_id, member.input_digest)
        answer = load_expected(directory / "labels", member.case_id, member.labels_digest)
        evidence = {item.id: item for item in incident.evidence}
        if not set(answer.required_evidence_ids).issubset(evidence):
            raise ValueError("expected answer cites missing evidence")
        if answer.expected_status == "resolved":
            support = [evidence[key] for key in answer.required_evidence_ids]
            if any(item.coverage != "complete" for item in support):
                raise ValueError("resolved answer relies on missing telemetry")
            if (
                len({item.modality for item in support}) < 2
                or len({item.provenance_group for item in support}) < 2
            ):
                raise ValueError("resolved answer needs independently sourced modalities")
        # Ignore the neutral case ID when detecting exact evidence duplicates.
        input_value = parse_json(incident.model_dump_json(exclude={"case_id"}))
        fingerprint = content_digest(input_value)
        group = (member.lineage_id, member.duplicate_cluster_id)
        if fingerprint in seen_inputs and seen_inputs[fingerprint] != group:
            raise ValueError("duplicate inputs must share lineage and cluster")
        seen_inputs[fingerprint] = group
    return manifest
