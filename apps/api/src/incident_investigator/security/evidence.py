"""Sanitization and sink gates. Unknown free-text formats are omitted, not certified safe."""

import math
import re
from dataclasses import dataclass, field
from typing import Annotated, Literal, cast

from pydantic import Field

from incident_investigator.evaluation.canonical import JSONValue, canonical_bytes, content_digest
from incident_investigator.evaluation.models import Contract, Identifier, Text
from incident_investigator.security.policy import Account, Resource

SANITIZER_VERSION = "1.0.0"
RULES = (
    re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.S),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", re.I),
    re.compile(
        r"\b(?:password|passwd|secret|token|api[_-]?key|authorization|credential)\s*[:=]\s*[^\s,;]+",
        re.I,
    ),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"https?://\S+", re.I),
)
# Only these structured scalar fields are retained in v1. Arbitrary message,
# stack, tag, trace payload and model prose need reviewed extraction templates.
ALLOWED_FIELDS = {"error_code", "operation", "status", "metric_name", "value", "unit"}


@dataclass(repr=False, frozen=True)
class RawEvidence:
    account_id: str
    region: str
    resource: str
    fields: dict[str, object] = field(repr=False)


class EvidenceField(Contract):
    name: Literal["error_code", "operation", "status", "metric_name", "value", "unit"]
    value: Annotated[str, Field(max_length=256)]


class SanitizedEvidence(Contract):
    id: Identifier
    sanitizer_version: Literal["1.0.0"]
    account_id: Account
    region: Identifier
    resource: Resource
    fields: Annotated[tuple[EvidenceField, ...], Field(min_length=1, max_length=6)]


class SanitizationResult(Contract):
    coverage: Literal["sanitized", "omitted"]
    reason: Literal["structured_fields_only", "unsupported_payload", "scope_denied"]
    evidence: SanitizedEvidence | None


def redact(value: str) -> str:
    for rule in RULES:
        value = rule.sub("[REDACTED]", value)
    return value


def sanitize(
    raw: RawEvidence, account: str, region: str, resources: tuple[str, ...]
) -> SanitizationResult:
    def omitted(reason: Literal["unsupported_payload", "scope_denied"]) -> SanitizationResult:
        return SanitizationResult(coverage="omitted", reason=reason, evidence=None)

    if (raw.account_id, raw.region) != (account, region) or raw.resource not in resources:
        return omitted("scope_denied")
    if len(raw.fields) > 100:
        return omitted("unsupported_payload")
    if redact(raw.resource) != raw.resource or any(ord(c) < 32 for c in raw.resource):
        return omitted("unsupported_payload")
    values: list[EvidenceField] = []
    for name in sorted(ALLOWED_FIELDS):
        value = raw.fields.get(name)
        if value is None:
            continue
        if type(value) not in (str, int, float) or len(str(value)) > 256:
            return omitted("unsupported_payload")
        if isinstance(value, float) and not math.isfinite(value):
            return omitted("unsupported_payload")
        cleaned = redact(str(value))
        # Structured tokens only. Omit hidden controls, encoded blobs, and prose.
        if cleaned != "[REDACTED]" and not re.fullmatch(r"[A-Za-z0-9_.:/% -]{1,64}", cleaned):
            return omitted("unsupported_payload")
        values.append(EvidenceField.model_validate({"name": name, "value": cleaned}))
    if not values:
        return omitted("unsupported_payload")
    payload: dict[str, JSONValue] = {
        "sanitizer_version": SANITIZER_VERSION,
        "account_id": account,
        "region": region,
        "resource": raw.resource,
        "fields": cast(JSONValue, [value.model_dump(mode="json") for value in values]),
    }
    identifier = "ev-" + content_digest(payload)[7:]
    record = SanitizedEvidence.model_validate_json(canonical_bytes({"id": identifier, **payload}))
    return SanitizationResult(
        coverage="sanitized", reason="structured_fields_only", evidence=record
    )


def evidence_bytes(
    records: tuple[SanitizedEvidence, ...], account: str, region: str, resources: tuple[str, ...]
) -> bytes:
    """The shared gate for storage, checkpoints, model requests, streams and exports."""
    if len(records) > 100:
        raise ValueError("evidence_limit")
    validated: list[JSONValue] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, SanitizedEvidence):
            raise ValueError("sanitized_evidence_required")
        record = SanitizedEvidence.model_validate_json(record.model_dump_json())
        if len({item.name for item in record.fields}) != len(record.fields):
            raise ValueError("duplicate_evidence_field")
        result = sanitize(
            RawEvidence(
                record.account_id,
                record.region,
                record.resource,
                {item.name: item.value for item in record.fields},
            ),
            account,
            region,
            resources,
        )
        if result.evidence != record or record.id in seen:
            raise ValueError("evidence_integrity_or_scope_failure")
        seen.add(record.id)
        validated.append(cast(JSONValue, record.model_dump(mode="json")))
    return canonical_bytes(validated)


class ReportClaim(Contract):
    text: Text
    evidence_ids: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=100)]


def publication_bytes(
    claims: tuple[ReportClaim, ...],
    records: tuple[SanitizedEvidence, ...],
    account: str,
    region: str,
    resources: tuple[str, ...],
    historical_case_ids: tuple[str, ...] = (),
) -> bytes:
    evidence_bytes(records, account, region, resources)
    if historical_case_ids:
        # Precision approval, runbook currency and canonical-case authority do not
        # exist yet. Never substitute caller assertions for those checks.
        raise ValueError("historical_publication_disabled")
    if not claims or len(claims) > 100:
        raise ValueError("claim_limit")
    known = {record.id for record in records}
    for claim in claims:
        claim = ReportClaim.model_validate_json(claim.model_dump_json())
        if not set(claim.evidence_ids).issubset(known):
            raise ValueError("fabricated_citation")
        if redact(claim.text) != claim.text or any(ord(c) < 32 for c in claim.text):
            raise ValueError("unsafe_claim")
    return canonical_bytes(cast(JSONValue, [claim.model_dump(mode="json") for claim in claims]))
