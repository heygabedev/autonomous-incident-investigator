import math
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from incident_investigator.evaluation.canonical import content_digest
from incident_investigator.evaluation.models import Contract, Digest, Identifier, Timestamp
from incident_investigator.providers.bedrock import EmbeddingConfig
from incident_investigator.workflow.contracts import Cause, ReplayInput
from incident_investigator.workflow.reasoning import PLANS


def digest(value: Contract) -> str:
    return content_digest(value.model_dump(mode="json"))


class Runbook(Contract):
    id: Identifier
    revision: Annotated[int, Field(ge=1, le=10000)]
    cause: Cause
    state: Literal["pending", "verified", "superseded", "revoked"]
    reviewed_at: Timestamp
    expires_at: Timestamp
    template_digest: Digest

    @model_validator(mode="after")
    def check_template(self) -> Self:
        if self.template_digest != content_digest(list(PLANS[self.cause])):
            raise ValueError("runbook_template_mismatch")
        if self.reviewed_at >= self.expires_at:
            raise ValueError("runbook_window")
        return self


class MemoryCase(Contract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    source: Literal["synthetic_development"] = "synthetic_development"
    id: Identifier
    revision: Annotated[int, Field(ge=1, le=10000)]
    parent_digest: Digest | None = None
    lineage_id: Identifier
    duplicate_cluster_id: Identifier
    incident: ReplayInput
    resolved_at: Timestamp
    revision_created_at: Timestamp
    valid_until: Timestamp
    state: Literal["pending", "verified", "superseded", "revoked"]
    verified_cause: Cause
    runtime_memory_approved: bool = False
    evaluation_approved: bool = False
    runbook: Runbook

    @model_validator(mode="after")
    def check_case(self) -> Self:
        if self.incident.case_id != self.id:
            raise ValueError("case_identity")
        if not self.incident.investigation_cutoff <= self.resolved_at < self.valid_until:
            raise ValueError("resolution_window")
        if self.revision_created_at < self.resolved_at:
            raise ValueError("revision_precedes_resolution")
        if self.verified_cause != self.runbook.cause:
            raise ValueError("runbook_cause")
        if (self.revision == 1) != (self.parent_digest is None):
            raise ValueError("case_parent")
        if self.state != "verified" and (self.runtime_memory_approved or self.evaluation_approved):
            raise ValueError("unverified_approval")
        return self


class Query(Contract):
    incident: ReplayInput
    lineage_id: Identifier
    duplicate_cluster_id: Identifier


class DocumentVector(Contract):
    document_digest: Digest
    embedding_fingerprint: Digest
    values: Annotated[tuple[float, ...], Field(min_length=256, max_length=1024)]

    @model_validator(mode="after")
    def check_vector(self) -> Self:
        if not all(math.isfinite(item) and abs(item) <= 1 for item in self.values):
            raise ValueError("invalid_vector")
        if abs(math.fsum(item * item for item in self.values) - 1) > 0.0001:
            raise ValueError("vector_not_normalized")
        return self


class VectorPair(Contract):
    evidence: DocumentVector
    cause: DocumentVector


class IndexDocument(Contract):
    case_id: Identifier
    case_digest: Digest
    evidence_terms: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=500)]
    cause_terms: Annotated[tuple[Identifier, ...], Field(max_length=4)]
    vectors: VectorPair


class IndexGeneration(Contract):
    id: Identifier
    source: Literal["synthetic_development"] = "synthetic_development"
    embedding: EmbeddingConfig
    feature_schema: Literal["history-features-v1"] = "history-features-v1"
    fusion: Literal["rrf-60-bm25-cosine-structured-v1"] = "rrf-60-bm25-cosine-structured-v1"
    documents: Annotated[tuple[IndexDocument, ...], Field(max_length=1000)]

    @model_validator(mode="after")
    def check_documents(self) -> Self:
        if len({item.case_id for item in self.documents}) != len(self.documents):
            raise ValueError("duplicate_index_case")
        for item in self.documents:
            for vector in (item.vectors.evidence, item.vectors.cause):
                if len(vector.values) != self.embedding.dimensions:
                    raise ValueError("index_dimensions")
                if vector.embedding_fingerprint != digest(self.embedding):
                    raise ValueError("index_embedding_mismatch")
        return self


class Match(Contract):
    case_id: Identifier
    case_digest: Digest
    index_fingerprint: Digest
    query_digest: Digest
    rank: Annotated[int, Field(ge=1, le=20)]
    fusion_score: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    # Ranking scores are NOT same-cause or applicability probabilities.
    calibrated: Literal[False] = False
