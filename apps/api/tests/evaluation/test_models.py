import json

import pytest
from incident_investigator.evaluation.artifacts import parse_artifact, parse_envelope, seal
from incident_investigator.evaluation.models import CandidateBundle
from pydantic import ValidationError

from .factories import artifact, payload


@pytest.mark.parametrize(
    "kind",
    [
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
    ],
)
def test_all_artifact_kinds_have_verified_roundtrips(kind: str) -> None:
    envelope = seal(artifact(kind))
    assert parse_envelope(envelope.to_bytes()) == envelope
    assert envelope.reference().kind == kind


def test_payload_tampering_fails_integrity_validation() -> None:
    data = json.loads(seal(artifact()).to_bytes())
    data["payload"]["budgets"]["model_calls"] = 7
    with pytest.raises(ValidationError, match="digest mismatch"):
        parse_envelope(json.dumps(data))


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", "01.0.0"),
        ("created_at", "2026-02-30T00:00:00Z"),
        ("created_at", "2026-09-25T12:00:00+00:00"),
        ("schema_version", "2.0.0"),
        ("cause_threshold_ppm", 899_999),
        ("cause_threshold_ppm", "900000"),
        ("cause_threshold_ppm", True),
        ("historical_actions_enabled", True),
        ("code_sha", "main"),
        ("unknown_field", "sensitive-input"),
    ],
)
def test_candidate_contract_rejects_unsafe_or_ambiguous_settings(field: str, value: object) -> None:
    data = payload()
    data[field] = value
    with pytest.raises(ValidationError):
        parse_artifact(json.dumps(data))


def test_nested_contracts_are_immutable() -> None:
    candidate = artifact()
    assert isinstance(candidate, CandidateBundle)
    with pytest.raises(ValidationError):
        candidate.budgets.model_calls = 7
    with pytest.raises(ValidationError):
        candidate.prompts[0].digest = "sha256:" + "b" * 64


def test_bypassed_pydantic_copy_is_revalidated_when_sealed() -> None:
    candidate = artifact()
    broken = candidate.model_copy(update={"version": "invalid"})
    with pytest.raises(ValidationError):
        seal(broken)


@pytest.mark.parametrize(
    "kind,path,value",
    [
        ("candidate_bundle", ("model", "inference_destinations"), ["eu-west-1"]),
        ("candidate_bundle", ("budgets", "model_calls"), 9),
        (
            "candidate_bundle",
            ("calibration",),
            {
                "kind": "case_revision",
                "id": "x",
                "version": "1.0.0",
                "digest": "sha256:" + "a" * 64,
            },
        ),
        ("case_revision", ("candidate_input", "case_id"), "other"),
        ("case_revision", ("source",), "sanitized_real"),
        ("case_revision", ("lifecycle",), "revoked"),
        ("case_revision", ("permitted_uses",), ["development", "development"]),
        ("dataset_snapshot", ("members", 0, "case", "kind"), "candidate_bundle"),
        ("calibration_artifact", ("training_snapshot", "kind"), "case_revision"),
        ("eval_suite", ("name",), "candidate-live"),
        ("eval_suite", ("datasets", 0, "kind"), "case_revision"),
        ("eval_suite", ("gates", 0, "slices", 0, "count"), 0),
        ("eval_run", ("candidate", "kind"), "case_revision"),
        ("promotion_decision", ("champion", "kind"), "case_revision"),
        ("promotion_decision", ("qualifying_runs", 0, "kind"), "case_revision"),
        ("promotion_decision", ("rollback_target", "kind"), "case_revision"),
        ("release_bundle", ("candidate", "kind"), "case_revision"),
        ("release_bundle", ("application_artifacts", 0, "name"), "unknown"),
        ("release_bundle", ("compatibility", 0, "name"), "sse"),
        ("exposure", ("disclosure",), "row_level"),
        ("exposure", ("dataset", "kind"), "case_revision"),
        ("exposure", ("case_ids",), ["x", "x"]),
    ],
)
def test_cross_field_invariants(kind: str, path: tuple[str | int, ...], value: object) -> None:
    data = payload(kind)
    target = data
    for segment in path[:-1]:
        target = target[segment]
    target[path[-1]] = value
    with pytest.raises(ValidationError):
        parse_artifact(json.dumps(data))
