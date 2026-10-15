import json
from pathlib import Path
from typing import Any

import pytest
from incident_investigator.memory.admission import preview
from incident_investigator.memory.calibration import AdmissionPin, features, fit
from incident_investigator.memory.contracts import digest
from incident_investigator.memory.retrieval import build_index
from incident_investigator.security.evidence import publication_bytes
from incident_investigator.security.policy import Broker, SecurityContext, SecurityPolicy
from incident_investigator.workflow.runtime import runtime_digest

from .samples import EMBED, case, case_vectors, query, query_vectors, store
from .test_calibration import pairs

SCENARIOS = json.loads(
    (
        Path(__file__).resolve().parents[4]
        / "fixtures/evaluation/history/v1/admission-scenarios.json"
    ).read_text()
)


def arguments() -> dict[str, Any]:
    current, previous = query(), case()
    repository = store(previous)
    generation = build_index(
        "generation-1", repository, EMBED, {previous.id: case_vectors(previous)}
    )
    pin = AdmissionPin(index_fingerprint=digest(generation), reasoning_fingerprint=runtime_digest())
    calibration = fit(pin, pairs("calibration", values=features(current, previous)))
    policy = SecurityPolicy(
        id="history-policy",
        revision=1,
        expires_at=100,
        account_id=current.incident.account_id,
        region=current.incident.region,
        resources=(current.incident.resource,),
        operations=("history.read",),
        templates=("synthetic-history-v1",),
        result_limit=20,
        remaining_microdollars=0,
    )
    context = SecurityContext(
        actor_id="operator",
        candidate_id="synthetic-preview",
        policy_id=policy.id,
        account_id=current.incident.account_id,
        region=current.incident.region,
    )
    return {
        "query": current,
        "vectors": query_vectors(),
        "generation": generation,
        "pin": pin,
        "calibration": calibration,
        "held_out": pairs("held_out"),
        "store": repository,
        "now": current.incident.investigation_cutoff,
        "context": context,
        "policy": policy,
        "broker": Broker(lambda: policy, lambda *_: None, lambda: 0),
    }


def test_preview_passes_synthetic_gates_without_enabling_publication() -> None:
    args = arguments()
    result = preview(**args)
    assert result.status == "gates_passed"
    assert not result.publication_allowed and not result.promotion_eligible
    assert len(result.actions) == 1
    action = result.actions[0]
    assert action.case_digest == digest(case())
    assert action.risk and action.rollback and action.validation and action.prerequisites
    assert action.probabilities.same_cause_ppm >= 900000
    assert action.probabilities.applicability_ppm >= 900000
    with pytest.raises(ValueError, match="historical_publication_disabled"):
        publication_bytes(
            (),
            (),
            args["query"].incident.account_id,
            args["query"].incident.region,
            (args["query"].incident.resource,),
            (action.case_id,),
        )


@pytest.mark.parametrize(
    "mutation,expected_status",
    [(item["mutation"], item["expected_status"]) for item in SCENARIOS["cases"]],
)
def test_all_admission_failures_remove_actions(mutation: str, expected_status: str) -> None:
    args = arguments()
    previous = case()
    if mutation == "precision":
        args["held_out"] = pairs("held_out", 99)
    elif mutation in ("index", "reasoning"):
        field = "index_fingerprint" if mutation == "index" else "reasoning_fingerprint"
        args["pin"] = args["pin"].model_copy(update={field: "sha256:" + "0" * 64})
    elif mutation == "policy":
        args["pin"] = args["pin"].model_copy(update={"cause_threshold_ppm": 999999})
    elif mutation in ("same_cause", "applicability"):
        training = pairs("calibration")
        training = tuple(
            item.model_copy(
                update={
                    "same_cause": mutation != "same_cause",
                    "action_applicable": False,
                }
            )
            for item in training
        )
        args["calibration"] = fit(args["pin"], training)
    elif mutation == "runbook":
        args["store"].put_runbook(
            previous.runbook.model_copy(update={"revision": 2, "state": "revoked"}),
            digest(previous.runbook),
        )
    elif mutation == "case":
        args["store"].put(
            previous.model_copy(
                update={
                    "revision": 2,
                    "parent_digest": digest(previous),
                    "state": "revoked",
                    "runtime_memory_approved": False,
                }
            ),
            digest(previous),
        )
    elif mutation in ("safe_mode", "feature", "candidate"):
        change = (
            {"safe_mode": True}
            if mutation == "safe_mode"
            else {"disabled_features": ("history",)}
            if mutation == "feature"
            else {"revoked_candidates": (args["context"].candidate_id,)}
        )
        current_policy = args["policy"].model_copy(update=change)
        args["broker"] = Broker(lambda: current_policy, lambda *_: None, lambda: 0)
    elif mutation == "audit":

        def broken_audit(*_: object) -> None:
            raise OSError("secret=seeded-secret")

        args["broker"] = Broker(lambda: args["policy"], broken_audit, lambda: 0)
    else:

        def broken_read(_: str) -> Any:
            raise OSError("secret=seeded-secret")

        args["store"].read = broken_read
    result = preview(**args)
    assert not result.actions and result.status == expected_status
    assert "seeded-secret" not in result.model_dump_json()


def test_golden_scenarios_are_explicitly_development_only() -> None:
    assert SCENARIOS["promotion_eligible"] is False
    assert SCENARIOS["permitted_use"] == "development"
    assert len({item["mutation"] for item in SCENARIOS["cases"]}) == len(SCENARIOS["cases"])


def test_two_modalities_with_shared_provenance_are_not_independent() -> None:
    args = arguments()
    incident = args["query"].incident
    observations = tuple(
        item.model_copy(update={"provenance_group": "single-source"})
        for item in incident.observations
    )
    current = args["query"].model_copy(
        update={"incident": incident.model_copy(update={"observations": observations})}
    )
    args["query"], args["vectors"] = current, query_vectors(current)
    # Even optimistically labeled calibration cannot bypass deterministic support checks.
    args["calibration"] = fit(args["pin"], pairs("calibration", values=features(current, case())))
    args["held_out"] = pairs("held_out", values=features(current, case()))
    assert not preview(**args).actions


def test_canonical_case_is_rechecked_after_retrieval() -> None:
    args = arguments()
    repository = args["store"]
    original_read = repository.read
    count = 0

    def changing_read(case_id: str) -> Any:
        nonlocal count
        count += 1
        current = original_read(case_id)
        if count == 2:
            repository.put(
                current.model_copy(
                    update={
                        "revision": 2,
                        "parent_digest": digest(current),
                        "state": "revoked",
                        "runtime_memory_approved": False,
                    }
                ),
                digest(current),
            )
        return original_read(case_id)

    repository.read = changing_read
    assert preview(**args).status == "failed_closed"


def test_containment_during_calculation_discards_preview() -> None:
    args = arguments()
    state = args["policy"]
    original_read = args["store"].read

    def contain(case_id: str) -> Any:
        nonlocal state
        state = state.model_copy(update={"revision": 2, "safe_mode": True})
        return original_read(case_id)

    args["store"].read = contain
    args["broker"] = Broker(lambda: state, lambda *_: None, lambda: 0)
    assert preview(**args).status == "failed_closed"
