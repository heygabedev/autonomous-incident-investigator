"""Schema validation, canonical envelopes, and fingerprints."""

from __future__ import annotations

import hmac
from typing import Literal, Self, cast

from pydantic import TypeAdapter, model_validator

from incident_investigator.evaluation.canonical import (
    JSONValue,
    canonical_bytes,
    content_digest,
    parse_json,
)
from incident_investigator.evaluation.models import (
    Artifact,
    ArtifactRef,
    Contract,
    Digest,
    RetrievalConfiguration,
)

ARTIFACT_ADAPTER: TypeAdapter[Artifact] = TypeAdapter(Artifact)


def parse_artifact(raw: bytes | str) -> Artifact:
    return ARTIFACT_ADAPTER.validate_json(canonical_bytes(parse_json(raw)), strict=True)


def payload_bytes(artifact: Artifact) -> bytes:
    return canonical_bytes(cast(JSONValue, artifact.model_dump(mode="json")))


class ArtifactEnvelope(Contract):
    canonicalization: Literal["jcs-safe-v1"] = "jcs-safe-v1"
    digest: Digest
    payload: Artifact

    @model_validator(mode="after")
    def verify_digest(self) -> Self:
        expected = content_digest(cast(JSONValue, self.payload.model_dump(mode="json")))
        if not hmac.compare_digest(self.digest, expected):
            raise ValueError("artifact digest mismatch")
        return self

    def reference(self) -> ArtifactRef:
        return ArtifactRef(
            kind=self.payload.kind,
            id=self.payload.id,
            version=self.payload.version,
            digest=self.digest,
        )

    def to_bytes(self) -> bytes:
        return canonical_bytes(cast(JSONValue, self.model_dump(mode="json")))


def seal(artifact: Artifact) -> ArtifactEnvelope:
    # Revalidate because Pydantic's model_copy/model_construct can bypass validators.
    validated = parse_artifact(payload_bytes(artifact))
    return ArtifactEnvelope(
        digest=content_digest(cast(JSONValue, validated.model_dump(mode="json"))),
        payload=validated,
    )


def parse_envelope(raw: bytes | str) -> ArtifactEnvelope:
    return ArtifactEnvelope.model_validate_json(canonical_bytes(parse_json(raw)), strict=True)


def retrieval_fingerprint(configuration: RetrievalConfiguration) -> str:
    return content_digest(cast(JSONValue, configuration.model_dump(mode="json")))
