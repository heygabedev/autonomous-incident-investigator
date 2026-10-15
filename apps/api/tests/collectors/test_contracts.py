import json
from typing import Any

import boto3
import pytest
from botocore.config import Config
from botocore.stub import Stubber
from incident_investigator.collectors.contracts import CollectionRequest, Template
from incident_investigator.collectors.replay import Exchange, RecordedTape, replay
from incident_investigator.collectors.requests import (
    METRICS,
    authorization_request,
    compile_request,
    query_call,
)
from incident_investigator.security.policy import (
    Broker,
    OperationDenied,
    SecurityContext,
    SecurityPolicy,
)
from pydantic import ValidationError

from .samples import ACCOUNT, QUERY, REGION, TARGETS, request, response


@pytest.mark.parametrize("template", list(TARGETS))
def test_fixed_requests_and_recorded_outputs_match_the_aws_sdk(template: Template) -> None:
    scope = request(template)
    call = compile_request(scope)
    # Explicit fake credentials and Stubber ensure no credential provider or network is used.
    client = boto3.client(
        call.service,
        region_name=REGION,
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        config=Config(retries={"total_max_attempts": 1}),
    )
    raw = {"queryId": QUERY} if template == "structured_logs_v1" else response(template)
    with Stubber(client) as stub:
        stub.add_response(call.method, raw, call.parameters)
        result = getattr(client, call.method)(**call.parameters)
        assert result == raw
        stub.assert_no_pending_responses()
    exchanges = [Exchange(call, raw)]
    if template == "structured_logs_v1":
        poll = query_call(QUERY)
        with Stubber(client) as stub:
            stub.add_response(poll.method, response(template), poll.parameters)
            result = getattr(client, poll.method)(**poll.parameters)
            exchanges.append(Exchange(poll, result))
    result = replay(scope, RecordedTape(tuple(exchanges)))
    assert result.observations
    assert "private" not in result.model_dump_json()
    assert "10.0.0.1" not in result.model_dump_json()
    assert all(item.evidence.resource == scope.resource for item in result.observations)
    assert all(item.evidence.account_id == ACCOUNT for item in result.observations)
    expected = (
        "sample"
        if template in METRICS
        else "window_aggregate"
        if template == "structured_logs_v1"
        else "snapshot"
    )
    assert {item.temporal_scope for item in result.observations} == {expected}
    client.close()


@pytest.mark.parametrize(
    "change",
    [
        {"account_id": "111111111111"},
        {"region": "us-east-1"},
        {"resource": "arn:aws:lambda:eu-central-1:000000000000:function:*"},
        {"resource": "arn:aws-cn:lambda:eu-central-1:000000000000:function:checkout"},
        {"resource": "https://attacker.example"},
        {"template": "lambda.delete_function"},
        {"query": "SOURCE accountId = 111111111111"},
        {"endpoint_url": "https://attacker.example"},
        {"result_limit": 101},
        {"max_calls": 13},
        {"max_pages": 4},
        {"timeout_ms": 30001},
        {"window_end": 0},
        {"window_end": 1735699601},
    ],
)
def test_request_denials(change: dict[str, Any]) -> None:
    assert compile_request(request()).method == "get_metric_data"
    with pytest.raises(ValidationError):
        CollectionRequest.model_validate(request().model_dump() | change)


def test_compiler_revalidates_constructed_models_and_has_no_query_or_method_passthrough() -> None:
    with pytest.raises(ValidationError):
        compile_request(request().model_copy(update={"resource": "*"}))
    logs = compile_request(request("structured_logs_v1"))
    assert "SOURCE" not in logs.parameters["queryString"]
    assert "@message" not in logs.parameters["queryString"]
    assert logs.parameters["logGroupIdentifiers"] == [request("structured_logs_v1").resource]


@pytest.mark.parametrize("template", list(TARGETS))
def test_broker_never_dispatches_live_collectors_even_with_permissive_policy(
    template: Template,
) -> None:
    scope = request(template)
    action = authorization_request(scope)
    policy = SecurityPolicy(
        id="policy",
        revision=1,
        expires_at=100,
        account_id=ACCOUNT,
        region=REGION,
        resources=(scope.resource,),
        operations=(action.operation,),
        templates=(scope.template,),
        result_limit=100,
        remaining_microdollars=500_000,
    )
    context = SecurityContext(
        actor_id="operator",
        candidate_id="candidate",
        policy_id=policy.id,
        account_id=ACCOUNT,
        region=REGION,
    )
    decisions = []
    broker = Broker(
        lambda: policy, lambda _context, _request, decision: decisions.append(decision), lambda: 0
    )
    with pytest.raises(OperationDenied, match="live_adapter_disabled"):
        broker.dispatch(context, action, policy, lambda _: pytest.fail("live dispatch"))
    assert not decisions[0].allowed
    assert json.loads(action.model_dump_json())["cost_microdollars"] == 500_000
