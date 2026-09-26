import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from incident_investigator.evaluation.canonical import content_digest
from incident_investigator.evaluation.cli import app
from incident_investigator.evaluation.golden import (
    ExpectedAnswer,
    GoldenManifest,
    IncidentInput,
    load_expected,
    load_input,
    validate_golden_dataset,
)
from pydantic import ValidationError
from typer.testing import CliRunner

GOLDEN = Path(__file__).resolve().parents[4] / "fixtures/evaluation/golden/v1"


@pytest.fixture
def copied_dataset(tmp_path: Path) -> Path:
    return Path(shutil.copytree(GOLDEN, tmp_path / "golden"))


def read(path: Path) -> dict[str, Any]:
    return dict(json.loads(path.read_text(encoding="utf-8")))


def replace_case(root: Path, category: str, case_id: str, value: dict[str, Any]) -> None:
    (root / category / f"{case_id}.json").write_text(json.dumps(value), encoding="utf-8")
    manifest = read(root / "manifest.json")
    key = "input_digest" if category == "inputs" else "labels_digest"
    for member in manifest["members"]:
        if member["case_id"] == case_id:
            member[key] = content_digest(value)
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_seed_dataset_is_valid_and_not_a_promotion_benchmark() -> None:
    manifest = validate_golden_dataset(GOLDEN)
    assert len(manifest.members) == 6
    assert len({member.lineage_id for member in manifest.members}) == 5
    assert {member.split for member in manifest.members} == {"dev"}
    assert manifest.promotion_eligible is False
    workloads = {
        load_input(GOLDEN / "inputs", member.case_id, member.input_digest).workload
        for member in manifest.members
    }
    assert workloads == {"ecs_fargate", "lambda_serverless"}


def test_candidate_loader_never_opens_gold_labels(tmp_path: Path) -> None:
    manifest = validate_golden_dataset(GOLDEN)
    inputs = Path(shutil.copytree(GOLDEN / "inputs", tmp_path / "inputs"))
    for member in manifest.members:
        incident = load_input(inputs, member.case_id, member.input_digest)
        assert "acceptable_causes" not in incident.model_dump()
        assert "labels_digest" not in incident.model_dump()
    assert not (tmp_path / "labels").exists()


def test_injection_variant_preserves_gold_cause_and_lineage() -> None:
    manifest = validate_golden_dataset(GOLDEN)
    original, variant = manifest.members[0], manifest.members[5]
    expected = load_expected(GOLDEN / "labels", original.case_id, original.labels_digest)
    injected = load_expected(GOLDEN / "labels", variant.case_id, variant.labels_digest)
    assert expected.acceptable_causes == injected.acceptable_causes
    assert original.lineage_id == variant.lineage_id
    assert original.duplicate_cluster_id == variant.duplicate_cluster_id
    assert "follow_telemetry_instructions" in injected.forbidden_actions


def test_missing_evidence_requires_abstention() -> None:
    member = validate_golden_dataset(GOLDEN).members[4]
    answer = load_expected(GOLDEN / "labels", member.case_id, member.labels_digest)
    assert answer.expected_status == "unresolved"
    assert answer.acceptable_causes == ()


@pytest.mark.parametrize("category", ["inputs", "labels"])
def test_tampering_is_detected(copied_dataset: Path, category: str) -> None:
    path = copied_dataset / category / "case-001.json"
    value = read(path)
    value["case_id"] = "changed"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="digest mismatch"):
        validate_golden_dataset(copied_dataset)


@pytest.mark.parametrize(
    "mutation", ["future", "duplicate", "window", "outside", "identity", "gold"]
)
def test_invalid_input_is_rejected(copied_dataset: Path, mutation: str) -> None:
    value = read(copied_dataset / "inputs/case-001.json")
    if mutation == "future":
        value["evidence"][0]["observed_at"] = "2025-01-15T10:30:00Z"
    elif mutation == "duplicate":
        value["evidence"][1]["id"] = value["evidence"][0]["id"]
    elif mutation == "window":
        value["window_end"] = "2025-01-15T09:00:00Z"
    elif mutation == "outside":
        value["evidence"][0]["occurred_at"] = "2025-01-15T09:59:00Z"
    elif mutation == "identity":
        value["case_id"] = "case-999"
    else:
        value["acceptable_causes"] = ["leaked_answer"]
    replace_case(copied_dataset, "inputs", "case-001", value)
    with pytest.raises(ValueError):
        validate_golden_dataset(copied_dataset)


@pytest.mark.parametrize("mutation", ["citation", "identity", "execution", "duplicate", "cause"])
def test_invalid_labels_are_rejected(copied_dataset: Path, mutation: str) -> None:
    value = read(copied_dataset / "labels/case-001.json")
    if mutation == "citation":
        value["required_evidence_ids"] = ["nonexistent"]
    elif mutation == "identity":
        value["case_id"] = "case-999"
    elif mutation == "execution":
        value["forbidden_actions"] = ["other"]
    elif mutation == "duplicate":
        value["required_evidence_ids"] *= 2
    else:
        value["expected_status"] = "unresolved"
    replace_case(copied_dataset, "labels", "case-001", value)
    with pytest.raises(ValueError):
        validate_golden_dataset(copied_dataset)


@pytest.mark.parametrize("mutation", ["missing", "modality", "provenance"])
def test_resolved_cause_requires_independent_evidence(copied_dataset: Path, mutation: str) -> None:
    value = read(copied_dataset / "inputs/case-001.json")
    if mutation == "missing":
        value["evidence"][0]["coverage"] = "unavailable"
    elif mutation == "modality":
        value["evidence"][0]["modality"] = value["evidence"][1]["modality"]
    else:
        value["evidence"][0]["provenance_group"] = value["evidence"][1]["provenance_group"]
    replace_case(copied_dataset, "inputs", "case-001", value)
    with pytest.raises(ValueError):
        validate_golden_dataset(copied_dataset)


def test_duplicate_cases_must_share_groups(copied_dataset: Path) -> None:
    value = read(copied_dataset / "inputs/case-001.json")
    value["case_id"] = "case-002"
    replace_case(copied_dataset, "inputs", "case-002", value)
    with pytest.raises(ValueError, match="share lineage"):
        validate_golden_dataset(copied_dataset)


@pytest.mark.parametrize("field,value", [("promotion_eligible", True), ("permitted_use", "sealed")])
def test_public_seed_cannot_claim_sealed_eligibility(field: str, value: Any) -> None:
    manifest = read(GOLDEN / "manifest.json")
    manifest[field] = value
    with pytest.raises(ValidationError):
        GoldenManifest.model_validate_json(json.dumps(manifest))


def test_path_traversal_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="escapes"):
        load_input(tmp_path, "../outside", "sha256:" + "a" * 64)


def test_duplicate_manifest_member_rejected() -> None:
    manifest = read(GOLDEN / "manifest.json")
    manifest["members"].append(manifest["members"][0])
    with pytest.raises(ValidationError, match="duplicate dataset member"):
        GoldenManifest.model_validate_json(json.dumps(manifest))


def test_schema_contracts_are_strict() -> None:
    for model in (IncidentInput, ExpectedAnswer, GoldenManifest):
        assert model.model_config["extra"] == "forbid"
        assert model.model_config["frozen"] is True


def test_cli_validates_without_claiming_accuracy() -> None:
    result = CliRunner().invoke(app, ["golden", "validate", str(GOLDEN)])
    assert result.exit_code == 0, result.output
    output = json.loads(result.output)
    assert output["case_count"] == 6
    assert output["lineage_count"] == 5
    assert output["promotion_eligible"] is False
    assert "accuracy" not in output
