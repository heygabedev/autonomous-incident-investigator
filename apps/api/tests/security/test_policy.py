from typing import Any

import pytest
from incident_investigator.security.policy import (
    ActionRequest,
    Broker,
    OperationDenied,
    SecurityContext,
    SecurityPolicy,
    authorize,
)
from pydantic import ValidationError


def policy(**changes: Any) -> SecurityPolicy:
    return SecurityPolicy(
        **(
            {
                "id": "policy-1",
                "revision": 1,
                "expires_at": 1000,
                "account_id": "000000000000",
                "region": "eu-central-1",
                "resources": ("fixture-1",),
                "operations": ("fixture.read", "report.publish"),
                "templates": ("fixed-query",),
                "result_limit": 10,
                "remaining_microdollars": 100,
            }
            | changes
        )
    )


def request(**changes: Any) -> ActionRequest:
    return ActionRequest(
        **(
            {
                "operation": "report.publish",
                "account_id": "000000000000",
                "region": "eu-central-1",
                "resource": "fixture-1",
                "template": "fixed-query",
                "result_limit": 10,
                "cost_microdollars": 10,
            }
            | changes
        )
    )


CONTEXT = SecurityContext(
    actor_id="local",
    candidate_id="candidate-1",
    policy_id="policy-1",
    account_id="000000000000",
    region="eu-central-1",
)


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"account_id": "111111111111"}, "account_denied"),
        ({"region": "us-east-1"}, "region_denied"),
        ({"resource": "other"}, "resource_denied"),
        ({"operation": "ecs.delete_service"}, "operation_unregistered"),
        ({"operation": "cloudwatch.get_metric_data"}, "live_adapter_disabled"),
        ({"template": "arbitrary-query"}, "template_denied"),
        ({"result_limit": 11}, "result_limit"),
        ({"cost_microdollars": 101}, "budget_exceeded"),
    ],
)
def test_request_denials(changes: dict[str, Any], reason: str) -> None:
    assert authorize(CONTEXT, request(), policy(), policy(), 0).allowed
    assert authorize(CONTEXT, request(**changes), policy(), policy(), 0).reason == reason


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"id": "other"}, "policy_mismatch"),
        ({"expires_at": 0}, "policy_expired"),
        ({"safe_mode": True}, "contained"),
        ({"disabled_features": ("publication",)}, "feature_disabled"),
        ({"revoked_candidates": ("candidate-1",)}, "candidate_revoked"),
        ({"operations": ()}, "operation_denied"),
    ],
)
def test_current_restrictions_cannot_be_bypassed(changes: dict[str, Any], reason: str) -> None:
    assert authorize(CONTEXT, request(), policy(), policy(**changes), 0).reason == reason
    assert authorize(CONTEXT, request(), policy(**changes), policy(), 0).reason == reason


def test_missing_and_regressed_policy() -> None:
    assert authorize(CONTEXT, request(), policy(), None, 0).reason == "policy_unavailable"
    assert (
        authorize(CONTEXT, request(), policy(revision=2), policy(), 0).reason == "policy_regression"
    )
    assert authorize(
        CONTEXT, request(operation="fixture.read"), policy(), policy(safe_mode=True), 0
    ).allowed


def test_broker_audits_then_dispatches_and_fails_closed() -> None:
    events: list[str] = []
    broker = Broker(lambda: policy(), lambda *args: events.append("intent"), lambda: 0)
    result = broker.dispatch(CONTEXT, request(), policy(), lambda _: events.append("dispatch"))
    assert result is None
    assert events == ["intent", "dispatch"]
    with pytest.raises(OperationDenied):
        broker.dispatch(
            CONTEXT, request(operation="ecs.delete_service"), policy(), lambda _: pytest.fail()
        )


def test_audit_failure_and_revocation_race_never_dispatch() -> None:
    def audit(*args: Any) -> None:
        raise OSError("private path")

    with pytest.raises(OperationDenied, match="audit_unavailable"):
        Broker(lambda: policy(), audit, lambda: 0).dispatch(
            CONTEXT, request(), policy(), lambda _: pytest.fail()
        )
    state = [policy()]
    broker = Broker(
        lambda: state[0], lambda *args: state.__setitem__(0, policy(safe_mode=True)), lambda: 0
    )
    with pytest.raises(OperationDenied, match="policy_changed"):
        broker.dispatch(CONTEXT, request(), policy(), lambda _: pytest.fail())


def test_arbitrary_parameters_and_construction_bypass() -> None:
    with pytest.raises(ValidationError):
        request(endpoint_url="https://evil.example")
    forged = request().model_copy(update={"result_limit": -1})
    with pytest.raises(ValidationError):
        Broker(lambda: policy(), lambda *args: None, lambda: 0).dispatch(
            CONTEXT, forged, policy(), lambda _: pytest.fail()
        )


def test_policy_store_failure_never_falls_back() -> None:
    def fail() -> SecurityPolicy:
        raise OSError("private database path")

    with pytest.raises(OperationDenied, match="policy_unavailable"):
        Broker(fail, lambda *args: None, lambda: 0).dispatch(
            CONTEXT, request(), policy(), lambda _: pytest.fail()
        )
    clock = iter([0, 1000])
    with pytest.raises(OperationDenied, match="policy_changed"):
        Broker(lambda: policy(), lambda *args: None, lambda: next(clock)).dispatch(
            CONTEXT, request(), policy(), lambda _: pytest.fail()
        )
