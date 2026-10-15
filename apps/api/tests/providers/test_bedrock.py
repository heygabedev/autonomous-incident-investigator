import copy
from typing import Any

import boto3
import pytest
from botocore.config import Config
from botocore.stub import Stubber
from hypothesis import given
from hypothesis import strategies as st
from incident_investigator.evaluation.canonical import canonical_bytes
from incident_investigator.providers.bedrock import (
    EmbeddingConfig,
    EvidenceInput,
    ModelContractError,
    ReasoningConfig,
    authorization_request,
    embedding_request,
    embedding_request_digest,
    reasoning_request,
    replay_embedding,
    replay_reasoning,
    request_digest,
)
from incident_investigator.security.evidence import RawEvidence, sanitize
from incident_investigator.security.policy import (
    Broker,
    OperationDenied,
    SecurityContext,
    SecurityPolicy,
)

REGION = "eu-central-1"
CONFIG = ReasoningConfig(model_id="anthropic.claude-3-haiku-20240307-v1:0", region=REGION)
EMBED = EmbeddingConfig(region=REGION)


def data() -> EvidenceInput:
    evidence = sanitize(
        RawEvidence("000000000000", REGION, "checkout", {"error_code": "AccessDenied"}),
        "000000000000",
        REGION,
        ("checkout",),
    ).evidence
    assert evidence is not None
    return EvidenceInput(
        account_id="000000000000",
        region=REGION,
        resources=("checkout",),
        records=(evidence,),
    )


def response() -> dict[str, Any]:
    return {
        "output": {
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "toolUse": {
                            "toolUseId": "proposal-1",
                            "name": "record_hypotheses",
                            "input": {
                                "abstain": False,
                                "hypotheses": [
                                    {
                                        "cause": "execution_role_permission_removed",
                                        "evidence_ids": [data().records[0].id],
                                    }
                                ],
                            },
                        }
                    }
                ],
            }
        },
        "stopReason": "tool_use",
        "usage": {"inputTokens": 100, "outputTokens": 50, "totalTokens": 150},
        "metrics": {"latencyMs": 200},
    }


def replay(value: dict[str, Any]) -> Any:
    return replay_reasoning(
        CONFIG,
        data(),
        request_digest(CONFIG, reasoning_request(CONFIG, data())),
        canonical_bytes(value),
    )


def test_converse_sdk_contract_and_proposals_are_unverified() -> None:
    request = reasoning_request(CONFIG, data())
    client = boto3.client(
        "bedrock-runtime",
        region_name=REGION,
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        config=Config(retries={"total_max_attempts": 1}),
    )
    with Stubber(client) as stub:
        stub.add_response("converse", response(), request)
        assert replay(client.converse(**request)).verified is False
        stub.assert_no_pending_responses()
    client.close()


def test_abstention_is_a_valid_result_without_a_repair_call() -> None:
    value = response()
    value["output"]["message"]["content"][0]["toolUse"]["input"] = {
        "abstain": True,
        "hypotheses": [],
    }
    assert replay(value).output.abstain


@pytest.mark.parametrize("reason", ["max_tokens", "end_turn", "guardrail_intervened", "tool_useX"])
def test_incomplete_or_refused_reasoning_is_not_accepted(reason: str) -> None:
    value = response() | {"stopReason": reason}
    with pytest.raises(ModelContractError, match=r"^invalid_recorded_reasoning$"):
        replay(value)


@pytest.mark.parametrize(
    "mutation",
    [
        "foreign_citation",
        "duplicate_citation",
        "duplicate_cause",
        "command",
        "wrong_tool",
        "extra_text",
        "wrong_role",
        "inconsistent_abstain",
        "bad_usage",
        "over_budget",
    ],
)
def test_reject_poisoned_and_malformed_outputs(mutation: str) -> None:
    value = response()
    message = value["output"]["message"]
    tool = message["content"][0]["toolUse"]
    answer = tool["input"]
    if mutation == "foreign_citation":
        answer["hypotheses"][0]["evidence_ids"] = ["ev-fabricated"]
    elif mutation == "duplicate_citation":
        answer["hypotheses"][0]["evidence_ids"] *= 2
    elif mutation == "duplicate_cause":
        answer["hypotheses"] *= 2
    elif mutation == "command":
        answer["command"] = "delete everything; token=seeded-secret"
    elif mutation == "wrong_tool":
        tool["name"] = "execute_remediation"
    elif mutation == "extra_text":
        message["content"].append({"text": "token=seeded-secret"})
    elif mutation == "wrong_role":
        message["role"] = "user"
    elif mutation == "inconsistent_abstain":
        answer["abstain"] = True
    elif mutation == "bad_usage":
        value["usage"]["totalTokens"] = True
    else:
        value["usage"] = {"inputTokens": 100, "outputTokens": 1501, "totalTokens": 1601}
    with pytest.raises(ModelContractError) as error:
        replay(value)
    assert "seeded-secret" not in str(error.value)


def test_request_binding_includes_model_region_settings_and_evidence() -> None:
    digest = request_digest(CONFIG, reasoning_request(CONFIG, data()))
    changed = CONFIG.model_copy(update={"max_output_tokens": 1000})
    with pytest.raises(ModelContractError):
        replay_reasoning(changed, data(), digest, canonical_bytes(response()))
    with pytest.raises(ModelContractError):
        reasoning_request(CONFIG.model_copy(update={"region": "us-east-1"}), data())
    with pytest.raises(ValueError):
        reasoning_request(CONFIG.model_copy(update={"model_id": "eu.profile:0"}), data())
    with pytest.raises(ValueError):
        reasoning_request(CONFIG, data().model_copy(update={"account_id": "111111111111"}))


@pytest.mark.parametrize("dimensions", [256, 512, 1024])
def test_titan_sdk_request_and_normalized_response(dimensions: int) -> None:
    config = EmbeddingConfig.model_validate({"region": REGION, "dimensions": dimensions})
    request = embedding_request(config, data())
    raw = canonical_bytes(
        {"embedding": [1.0] + [0.0] * (dimensions - 1), "inputTextTokenCount": 10}
    )
    client = boto3.client(
        "bedrock-runtime",
        region_name=REGION,
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )
    with Stubber(client) as stub:
        stub.add_response("invoke_model", {"body": raw, "contentType": "application/json"}, request)
        result = client.invoke_model(**request)
        parsed = replay_embedding(
            config, data(), embedding_request_digest(config, data()), result["body"]
        )
        assert len(parsed.vector) == dimensions
    client.close()


@pytest.mark.parametrize(
    "mutation", ["size", "norm", "bool", "string", "tokens", "different", "extra"]
)
def test_embedding_integrity(mutation: str) -> None:
    value: dict[str, Any] = {"embedding": [1.0] + [0.0] * 255, "inputTextTokenCount": 10}
    if mutation == "size":
        value["embedding"].pop()
    elif mutation == "norm":
        value["embedding"][0] = 0.0
    elif mutation == "bool":
        value["embedding"][0] = True
    elif mutation == "string":
        value["embedding"][0] = "token=seeded-secret"
    elif mutation == "tokens":
        value["inputTextTokenCount"] = 0
    elif mutation == "different":
        value["embeddingsByType"] = {"float": [0.0] * 256}
    else:
        value["secret"] = "seeded-secret"
    with pytest.raises(ModelContractError):
        replay_embedding(
            EMBED, data(), embedding_request_digest(EMBED, data()), canonical_bytes(value)
        )


@given(st.binary(max_size=2000))
def test_untrusted_provider_bytes_never_escape_as_exceptions(raw: bytes) -> None:
    with pytest.raises(ModelContractError):
        replay_reasoning(
            CONFIG, data(), request_digest(CONFIG, reasoning_request(CONFIG, data())), raw
        )
    with pytest.raises(ModelContractError):
        replay_embedding(EMBED, data(), embedding_request_digest(EMBED, data()), raw)


@pytest.mark.parametrize("config", [CONFIG, EMBED])
def test_broker_denies_all_live_provider_dispatch(config: Any) -> None:
    action = authorization_request(config, data())
    policy = SecurityPolicy(
        id="policy",
        revision=1,
        expires_at=100,
        account_id=data().account_id,
        region=REGION,
        resources=(action.resource,),
        operations=(action.operation,),
        templates=(action.template,),
        result_limit=100,
        remaining_microdollars=500_000,
    )
    context = SecurityContext(
        actor_id="operator",
        candidate_id="candidate",
        policy_id="policy",
        account_id=data().account_id,
        region=REGION,
    )
    broker = Broker(lambda: policy, lambda *_: None, lambda: 0)
    with pytest.raises(OperationDenied, match="live_adapter_disabled"):
        broker.dispatch(context, action, policy, lambda _: pytest.fail("unexpected dispatch"))


def test_duplicate_json_keys_and_raw_evidence_are_rejected() -> None:
    raw = b'{"output":{},"output":{},"secret":"seeded-secret"}'
    with pytest.raises(ModelContractError):
        replay_reasoning(
            CONFIG, data(), request_digest(CONFIG, reasoning_request(CONFIG, data())), raw
        )
    modified = copy.deepcopy(data().model_dump())
    modified["records"] = (RawEvidence("000000000000", REGION, "checkout", {"message": "secret"}),)
    with pytest.raises(ValueError):
        EvidenceInput.model_validate(modified)


@pytest.mark.parametrize(
    "path,value",
    [
        (("output",), []),
        (("output", "message"), []),
        (("output", "message", "content"), []),
        (("output", "message", "content"), [{"text": "untrusted text"}]),
        (("usage",), []),
        (("usage", "inputTokens"), -1),
        (("usage", "inputTokens"), 80001),
        (("usage", "totalTokens"), 999),
    ],
)
def test_nested_response_shapes_and_usage_fail_closed(path: tuple[str, ...], value: Any) -> None:
    raw = response()
    container = raw
    for key in path[:-1]:
        container = container[key]
    container[path[-1]] = value
    with pytest.raises(ModelContractError):
        replay(raw)


def test_extra_tool_fields_and_missing_usage_fail_closed() -> None:
    raw = response()
    raw["output"]["message"]["content"][0]["toolUse"]["input"]["gold_labels"] = "secret"
    with pytest.raises(ModelContractError):
        replay(raw)
    raw = response()
    del raw["usage"]
    with pytest.raises(ModelContractError):
        replay(raw)


def test_embedding_is_bound_to_recorded_request_and_accepts_matching_float_views() -> None:
    value = {"embedding": [1.0] + [0.0] * 255, "inputTextTokenCount": 10}
    raw = canonical_bytes(value | {"embeddingsByType": {"float": value["embedding"]}})
    assert (
        replay_embedding(EMBED, data(), embedding_request_digest(EMBED, data()), raw).vector[0] == 1
    )
    with pytest.raises(ModelContractError):
        replay_embedding(EMBED, data(), "wrong-request", raw)


def test_provider_boundary_does_not_depend_on_python_assertions() -> None:
    import ast
    from pathlib import Path

    import incident_investigator.providers.bedrock as provider

    tree = ast.parse(Path(provider.__file__).read_text(encoding="utf-8"))
    assert not any(isinstance(node, ast.Assert) for node in ast.walk(tree))
