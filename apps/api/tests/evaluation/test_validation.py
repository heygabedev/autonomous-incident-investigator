import json
from pathlib import Path
from typing import Any

import pytest
from incident_investigator.evaluation.artifacts import parse_artifact, retrieval_fingerprint
from incident_investigator.evaluation.models import ArtifactRef, CandidateBundle
from incident_investigator.evaluation.registry import SQLiteRegistry
from incident_investigator.evaluation.validation import (
    EligibilityError,
    RegisteredDatasets,
    validate_candidate_links,
)

from .factories import DIGEST, payload
from .test_registry import register


@pytest.fixture
def store(tmp_path: Path) -> SQLiteRegistry:
    registry = SQLiteRegistry(tmp_path / "registry.sqlite3")
    registry.initialize()
    return registry


def dataset(store: SQLiteRegistry, cases: list[tuple[dict[str, Any], str]]) -> ArtifactRef:
    manifest = payload("dataset_snapshot")
    manifest["members"] = [
        {"case": register(store, case).model_dump(mode="json"), "split": split}
        for case, split in cases
    ]
    return register(store, manifest)


def test_runner_projection_contains_no_labels(store: SQLiteRegistry) -> None:
    reference = dataset(store, [(payload("case_revision"), "dev")])
    inputs = RegisteredDatasets(store).candidate_inputs(reference)
    assert len(inputs) == 1
    assert set(inputs[0].model_dump()) == {"case_id", "input_digest", "investigation_cutoff"}


@pytest.mark.parametrize("shared", ["lineage_id", "duplicate_cluster_id", "input"])
def test_cross_partition_leakage(store: SQLiteRegistry, shared: str) -> None:
    first = payload("case_revision", "first")
    second = payload("case_revision", "second")
    if shared != "input":
        second[shared] = first[shared]
        second["candidate_input"]["input_digest"] = "sha256:" + "b" * 64
    reference = dataset(store, [(first, "dev"), (second, "sealed_test")])
    with pytest.raises(EligibilityError, match="cross dataset partitions"):
        RegisteredDatasets(store).validate(reference)


@pytest.mark.parametrize(
    "changes",
    [
        {"lifecycle": "pending"},
        {"data_stage": "shadow"},
        {"permitted_uses": ["runtime_memory"]},
        {"source": "sanitized_real", "owner_approval_digest": DIGEST},
    ],
)
def test_ineligible_case(store: SQLiteRegistry, changes: dict[str, Any]) -> None:
    case = payload("case_revision") | changes
    reference = dataset(store, [(case, "dev")])
    with pytest.raises(EligibilityError):
        RegisteredDatasets(store).validate(reference)


@pytest.mark.parametrize("target", ["case", "dataset"])
def test_current_invalidation_blocks_old_snapshot(store: SQLiteRegistry, target: str) -> None:
    case = payload("case_revision")
    reference = dataset(store, [(case, "dev")])
    before = store.resolve(reference).to_bytes()
    event = payload("invalidation")
    event["target"] = (register(store, case) if target == "case" else reference).model_dump(
        mode="json"
    )
    register(store, event)
    with pytest.raises(EligibilityError, match="current invalidation"):
        RegisteredDatasets(store).validate(reference)
    assert store.resolve(reference).to_bytes() == before


def test_exposure_taints_sealed_case_across_snapshots(store: SQLiteRegistry) -> None:
    reference = dataset(store, [(payload("case_revision"), "sealed_test")])
    event = payload("exposure")
    event.update(disclosure="row_level", case_ids=["fixture"])
    register(store, event)
    with pytest.raises(EligibilityError, match="label exposure"):
        RegisteredDatasets(store).validate(reference)


def test_label_policy_must_match_snapshot(store: SQLiteRegistry) -> None:
    case = payload("case_revision")
    case["gold_labels"]["labeling_policy"]["version"] = "2.0.0"
    reference = dataset(store, [(case, "dev")])
    with pytest.raises(EligibilityError, match="labeling policy"):
        RegisteredDatasets(store).validate(reference)


@pytest.mark.parametrize("mutation", ["none", "index", "feature", "threshold", "training"])
def test_calibration_compatibility(store: SQLiteRegistry, mutation: str) -> None:
    split = "dev" if mutation == "training" else "calibration"
    training = dataset(store, [(payload("case_revision"), split)])
    candidate_payload = payload()
    candidate = parse_artifact(json.dumps(candidate_payload))
    assert isinstance(candidate, CandidateBundle)
    calibration = payload("calibration_artifact")
    calibration["training_snapshot"] = training.model_dump(mode="json")
    calibration["retrieval_fingerprint"] = retrieval_fingerprint(candidate.retrieval)
    if mutation == "index":
        candidate_payload["retrieval"]["index_generation"] = "different-generation"
    elif mutation == "feature":
        calibration["feature_schema"]["version"] = "2.0.0"
    elif mutation == "threshold":
        calibration["cause_threshold_ppm"] = 990_000
    candidate_payload["calibration"] = register(store, calibration).model_dump(mode="json")
    candidate_payload["historical_actions_enabled"] = True
    reference = register(store, candidate_payload)
    if mutation == "none":
        validate_candidate_links(store, reference)
    else:
        with pytest.raises(EligibilityError):
            validate_candidate_links(store, reference)


def test_no_calibration_is_valid_when_history_disabled(store: SQLiteRegistry) -> None:
    validate_candidate_links(store, register(store, payload()))


def test_wrong_reference_kind(store: SQLiteRegistry) -> None:
    reference = register(store, payload())
    with pytest.raises(EligibilityError, match="expected dataset"):
        RegisteredDatasets(store).validate(reference)
    reference = dataset(store, [(payload("case_revision"), "dev")])
    with pytest.raises(EligibilityError, match="expected candidate"):
        validate_candidate_links(store, reference)
