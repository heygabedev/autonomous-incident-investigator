"""Ports for separate runners, scorers and storage implementations."""

from typing import Protocol

from incident_investigator.evaluation.artifacts import ArtifactEnvelope
from incident_investigator.evaluation.models import (
    ArtifactRef,
    CandidateBundle,
    CandidateInput,
    Contract,
    Digest,
    GoldLabels,
    Kind,
)


class ArtifactStore(Protocol):
    def put(self, envelope: ArtifactEnvelope) -> ArtifactRef: ...
    def get(self, digest: str) -> ArtifactEnvelope: ...
    def resolve(self, reference: ArtifactRef) -> ArtifactEnvelope: ...
    def list_kind(self, kind: Kind) -> tuple[ArtifactEnvelope, ...]: ...


class DatasetStore(Protocol):
    def candidate_inputs(self, snapshot: ArtifactRef) -> tuple[CandidateInput, ...]: ...


class CandidateResult(Contract):
    input_digest: Digest
    output_digest: Digest
    trajectory_digest: Digest


class CandidateRunner(Protocol):
    def run(self, candidate: CandidateBundle, input: CandidateInput) -> CandidateResult: ...


class Metric(Protocol):
    def score(self, result: CandidateResult, labels: GoldLabels) -> ArtifactRef: ...


class Judge(Protocol):
    def assess(self, result: CandidateResult, labels: GoldLabels) -> ArtifactRef: ...


class ComparisonEngine(Protocol):
    def compare(self, baseline: ArtifactRef, challenger: ArtifactRef) -> ArtifactRef: ...
