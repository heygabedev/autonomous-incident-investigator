from typing import Any

import pytest
from incident_investigator.evaluation.canonical import content_digest, parse_json
from incident_investigator.security.policy import (
    Broker,
    OperationDenied,
    SecurityContext,
    SecurityPolicy,
)
from incident_investigator.workflow.contracts import RunPin, RunState
from incident_investigator.workflow.graph import build_graph, invoke
from incident_investigator.workflow.replay import prepare

from .test_replay import incident


def setup(index: int = 0) -> tuple[RunState, SecurityContext, SecurityPolicy]:
    value = prepare(incident(index))
    policy = SecurityPolicy(
        id="fixture-policy",
        revision=1,
        expires_at=2_000_000_000,
        account_id=value.account_id,
        region=value.region,
        resources=(value.resource,),
        operations=("fixture.read", "report.publish"),
        templates=("offline-investigation-v1",),
        result_limit=100,
        remaining_microdollars=0,
    )
    pin = RunPin(
        release_id="offline-release",
        candidate_id="offline-candidate",
        candidate_digest="sha256:" + "a" * 64,
        graph_digest="sha256:" + "b" * 64,
        policy_digest=content_digest(parse_json(policy.model_dump_json())),
    )
    state = RunState(
        attempt_id="attempt-1",
        pin=pin,
        incident=value,
        input_digest=content_digest(parse_json(value.model_dump_json())),
    )
    context = SecurityContext(
        actor_id="local",
        candidate_id=pin.candidate_id,
        policy_id=policy.id,
        account_id=value.account_id,
        region=value.region,
    )
    return state, context, policy


def execute(
    state: RunState, context: SecurityContext, policy: SecurityPolicy, **kwargs: Any
) -> RunState:
    broker = Broker(lambda: policy, lambda *args: None, lambda: 0)
    return invoke(build_graph(state.pin, context, policy, broker, **kwargs), state)


@pytest.mark.parametrize(
    "index,status,cause",
    [
        (0, "resolved", "missing_required_environment_variable"),
        (1, "resolved", "dynamodb_write_throttling"),
        (2, "resolved", "target_group_port_mismatch"),
        (3, "resolved", "execution_role_permission_removed"),
        (4, "unresolved", None),
        (5, "degraded", "missing_required_environment_variable"),
    ],
)
def test_golden_trajectories(index: int, status: str, cause: str | None) -> None:
    state = execute(*setup(index))
    assert state.report is not None and state.report.status == status
    assert state.next_stage == "done" and state.evidence_rounds == 0
    assert state.completed.index("hypothesize") < state.completed.index("history")
    assert len(state.collected) == 4
    if cause:
        assert state.report.recommendations[0].cause == cause
        assert state.report.recommendations[0].execution == "operator_only"
    else:
        assert not state.report.recommendations
    assert state.report.model_calls == 0 and state.report.cost_microdollars == 0


def test_two_rounds_then_no_more_and_deterministic_output() -> None:
    state, context, policy = setup()
    items = tuple(
        item.model_copy(update={"available_round": 2 if item.modality == "log" else 0})
        for item in state.incident.observations
    )
    value = state.incident.model_copy(update={"observations": items})
    state = state.model_copy(
        update={
            "incident": value,
            "input_digest": content_digest(parse_json(value.model_dump_json())),
        }
    )
    result = execute(state, context, policy)
    assert result.report is not None and result.report.status == "resolved"
    assert result.evidence_rounds == 2
    assert result.completed.count("collect") == 3
    assert result == execute(state, context, policy)
    limited = execute(state.model_copy(update={"round_limit": 1}), context, policy)
    assert limited.report is not None and limited.report.status == "unresolved"
    assert limited.evidence_rounds <= 1


def test_shared_provenance_prevents_confident_diagnosis() -> None:
    state, context, policy = setup()
    value = state.incident.model_copy(
        update={
            "observations": tuple(
                item.model_copy(update={"provenance_group": "same-source"})
                for item in state.incident.observations
            )
        }
    )
    state = state.model_copy(
        update={
            "incident": value,
            "input_digest": content_digest(parse_json(value.model_dump_json())),
        }
    )
    result = execute(state, context, policy)
    assert result.report is not None and result.report.status == "unresolved"


def test_mismatched_deployment_and_contradiction_abstain() -> None:
    for text in (
        incident().evidence[1].text.replace("revision 17", "revision 99"),
        "Application startup succeeds; all required configuration values are present.",
    ):
        state, context, policy = setup()
        value = incident()
        value = value.model_copy(
            update={
                "evidence": (
                    value.evidence[0],
                    value.evidence[1].model_copy(update={"text": text}),
                    value.evidence[2],
                )
            }
        )
        ready = prepare(value)
        state = state.model_copy(
            update={
                "incident": ready,
                "input_digest": content_digest(parse_json(ready.model_dump_json())),
            }
        )
        result = execute(state, context, policy)
        assert result.report is not None and result.report.status == "unresolved"
        assert not result.report.recommendations


def test_revocation_at_node_boundary_and_publication_containment() -> None:
    state, context, policy = setup()
    current = [policy]

    def checkpoint(_: RunState) -> None:
        current[0] = policy.model_copy(update={"revoked_candidates": (context.candidate_id,)})

    broker = Broker(lambda: current[0], lambda *args: None, lambda: 0)
    with pytest.raises(OperationDenied, match="candidate_revoked"):
        invoke(build_graph(state.pin, context, policy, broker, checkpoint), state)
    current[0] = policy.model_copy(update={"safe_mode": True})
    with pytest.raises(OperationDenied, match="contained"):
        invoke(build_graph(state.pin, context, policy, broker), state)


def test_pin_and_input_digest_mismatches_rejected() -> None:
    state, context, policy = setup()
    graph = build_graph(
        state.pin, context, policy, Broker(lambda: policy, lambda *args: None, lambda: 0)
    )
    for changes in (
        {"pin": state.pin.model_copy(update={"release_id": "other"})},
        {"input_digest": "sha256:" + "0" * 64},
    ):
        with pytest.raises(ValueError):
            invoke(graph, state.model_copy(update=changes))


def test_node_boundary_resume_matches_uninterrupted_result() -> None:
    state, context, policy = setup()
    paused = execute(state, context, policy, stop_after="verify")
    assert paused.report is None and paused.next_stage == "history"
    assert execute(paused, context, policy) == execute(state, context, policy)
