from typing import Any

import pytest
from incident_investigator.security.evidence import (
    RawEvidence,
    ReportClaim,
    evidence_bytes,
    publication_bytes,
    redact,
    sanitize,
)

ACCOUNT, REGION, RESOURCES = "000000000000", "eu-central-1", ("fixture-service",)


def raw(fields: dict[str, object]) -> RawEvidence:
    return RawEvidence(ACCOUNT, REGION, RESOURCES[0], fields)


def test_only_structured_fields_survive_and_have_stable_ids() -> None:
    result = sanitize(
        raw({"error_code": "AccessDeniedException", "message": "private raw log"}),
        ACCOUNT,
        REGION,
        RESOURCES,
    )
    assert result.evidence is not None
    assert (
        "private raw log"
        not in evidence_bytes((result.evidence,), ACCOUNT, REGION, RESOURCES).decode()
    )
    assert result == sanitize(
        raw({"error_code": "AccessDeniedException"}), ACCOUNT, REGION, RESOURCES
    )


@pytest.mark.parametrize(
    "secret",
    [
        "password=fixture-password",
        "Bearer fixture-token",
        "alice@example.invalid",
        "192.168.1.10",
        "123-45-6789",
        "https://example.invalid/?token=private",
        "-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----",
        "AKIA" + "A" * 16,
    ],
)
def test_seeded_secrets_are_removed(secret: str) -> None:
    assert secret not in redact(secret)
    result = sanitize(raw({"error_code": secret}), ACCOUNT, REGION, RESOURCES)
    assert result.evidence is not None
    assert secret not in evidence_bytes((result.evidence,), ACCOUNT, REGION, RESOURCES).decode()


@pytest.mark.parametrize(
    "fields",
    [
        {"message": "secret=do-not-keep"},
        {"value": {"nested": "raw"}},
        {"status": "x" * 300},
        {"error_code": "\u200bhidden"},
        {"status": "<script>alert(1)</script>"},
        {"status": "A" * 100},
    ],
)
def test_unsupported_payloads_become_coverage_gaps(fields: dict[str, Any]) -> None:
    result = sanitize(raw(fields), ACCOUNT, REGION, RESOURCES)
    assert result.coverage == "omitted"
    assert result.evidence is None
    assert "secret" not in repr(raw(fields))


def test_scope_forgery_and_raw_objects_fail_at_sink() -> None:
    result = sanitize(raw({"status": "failed"}), ACCOUNT, REGION, RESOURCES)
    assert result.evidence is not None
    assert (
        sanitize(raw({"status": "failed"}), "111111111111", REGION, RESOURCES).coverage == "omitted"
    )
    for forged in (
        raw({"status": "failed"}),
        result.evidence.model_copy(update={"id": "forged"}),
        result.evidence.model_copy(update={"resource": "other"}),
    ):
        with pytest.raises(ValueError):
            evidence_bytes((forged,), ACCOUNT, REGION, RESOURCES)  # type: ignore[arg-type]


def test_publication_rejects_fabrication_and_historical_assertions() -> None:
    evidence = sanitize(raw({"status": "failed"}), ACCOUNT, REGION, RESOURCES).evidence
    assert evidence is not None
    claim = ReportClaim(text="The request failed.", evidence_ids=(evidence.id,))
    assert publication_bytes((claim,), (evidence,), ACCOUNT, REGION, RESOURCES)
    for bad in (
        claim.model_copy(update={"evidence_ids": ("nonexistent",)}),
        claim.model_copy(update={"text": "password=private"}),
    ):
        with pytest.raises(ValueError):
            publication_bytes((bad,), (evidence,), ACCOUNT, REGION, RESOURCES)
    with pytest.raises(ValueError, match="historical_publication_disabled"):
        publication_bytes((claim,), (evidence,), ACCOUNT, REGION, RESOURCES, ("revoked-case",))
