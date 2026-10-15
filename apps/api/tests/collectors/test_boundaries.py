import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.stub import Stubber
from incident_investigator.collectors.contracts import CollectionError, Template
from incident_investigator.collectors.doctor import inspect_config
from incident_investigator.collectors.normalize import check_payload
from incident_investigator.collectors.replay import Exchange, RecordedTape, replay
from incident_investigator.collectors.requests import OPERATIONS, compile_request, query_call
from incident_investigator.security.cli import app
from incident_investigator.security.policy import OPERATIONS as BROKER_OPERATIONS
from typer.testing import CliRunner

from .samples import QUERY, REGION, START, TARGETS, request, response
from .test_doctor import CONFIG, REQUIREMENT


def test_review_inventory_covers_exact_registered_read_operations_without_activating_them() -> None:
    inventory = json.loads(Path("security/aws-collectors.json").read_text())
    assert inventory["kind"] == "review_inventory_not_deployable_policy"
    assert inventory["live_enabled"] is False
    expected = {".".join(pair) for pair in OPERATIONS.values()} | {
        "logs.get_query_results",
        "logs.stop_query",
    }
    assert {item["operation"] for item in inventory["operations"]} == expected
    for entry in inventory["operations"]:
        assert entry["access"] == "Read" and "*" not in entry["iam_action"]
        assert BROKER_OPERATIONS[entry["operation"]] == ("collection", True)
        assert set(entry["templates"]) <= set(TARGETS)
    assert {template for item in inventory["operations"] for template in item["templates"]} == set(
        TARGETS
    )


def test_query_cleanup_matches_sdk_and_never_accepts_external_query_ids() -> None:
    call = query_call(QUERY, stop=True)
    client = boto3.client(
        "logs", region_name=REGION, aws_access_key_id="testing", aws_secret_access_key="testing"
    )
    with Stubber(client) as stub:
        stub.add_response("stop_query", {"success": True}, call.parameters)
        assert client.stop_query(**call.parameters)["success"] is True
    client.close()
    for value in ("*", "https://external.example", "../query", QUERY + "/other"):
        with pytest.raises(ValueError, match="invalid_query_id"):
            query_call(value)


def test_cleanup_failure_is_visible_and_does_not_publish_partial_rows() -> None:
    scope = request("structured_logs_v1", max_calls=3)
    tape = (
        Exchange(compile_request(scope), {"queryId": QUERY}),
        Exchange(query_call(QUERY), {"status": "Running", "results": []}),
        Exchange(query_call(QUERY, stop=True), {"success": False}),
    )
    result = replay(scope, RecordedTape(tape))
    assert result.gaps == ("call_limit", "query_failed") and not result.observations
    denied = (*tape[:2], Exchange(query_call(QUERY, stop=True), error_code="AccessDeniedException"))
    assert replay(scope, RecordedTape(denied)).gaps == ("call_limit", "permission_denied")


def test_missing_and_oversized_tapes_do_not_dispatch() -> None:
    exchange = Exchange(compile_request(request()), response())
    with pytest.raises(ValueError):
        RecordedTape((exchange,) * 13)
    with pytest.raises(ValueError):
        RecordedTape((Exchange(exchange.call, elapsed_ms=-1),))


@pytest.mark.parametrize("template", list(TARGETS))
def test_unexpected_response_shapes_and_nulls_are_generic(template: Template) -> None:
    scope = request(template)
    for payload in ({}, {"private": "payload"}, response(template) | {"unexpected": b"private"}):
        result = replay(scope, RecordedTape((Exchange(compile_request(scope), payload),)))
        assert not result.observations and result.gaps
        assert "private" not in result.model_dump_json()


def test_ecs_failures_cluster_mismatch_and_snapshot_omissions() -> None:
    scope = request("ecs_service_v1")
    call = compile_request(scope)
    assert replay(
        scope, RecordedTape((Exchange(call, {"failures": [{"reason": "private"}]}),))
    ).gaps == ("unavailable",)
    raw = response(scope.template)
    raw["services"][0]["events"] = [{"message": "private event"}]
    result = replay(scope, RecordedTape((Exchange(call, raw),)))
    assert "restricted_fields_omitted" in result.gaps
    assert "private event" not in result.model_dump_json()
    raw["services"][0]["clusterArn"] = "foreign"
    assert replay(scope, RecordedTape((Exchange(call, raw),))).gaps == ("scope_mismatch",)


def test_log_duplicates_omissions_and_result_cap() -> None:
    scope = request("structured_logs_v1", result_limit=1)
    raw = response(scope.template)
    raw["results"][0].append({"field": "@ptr", "value": "private log pointer"})

    def run(payload: dict[str, Any]) -> Any:
        return replay(
            scope,
            RecordedTape(
                (
                    Exchange(compile_request(scope), {"queryId": QUERY}),
                    Exchange(query_call(QUERY), payload),
                )
            ),
        )

    result = run(raw)
    assert "result_limit" in result.gaps and "restricted_fields_omitted" in result.gaps
    assert "private" not in result.model_dump_json()
    raw["results"][0].append({"field": "status", "value": "failed"})
    assert run(raw).gaps == ("unsupported_payload",)
    for count in ("-1", "nan", "9" * 13, "\uff11\uff12", None):
        raw = response(scope.template)
        raw["results"][0][2]["value"] = count
        assert run(raw).gaps == ("unsupported_payload",)


def test_empty_complete_and_partial_series_are_distinct() -> None:
    raw = response()
    raw["MetricDataResults"][0].update(Values=[], Timestamps=[])
    call = compile_request(request())
    result = replay(request(), RecordedTape((Exchange(call, raw),)))
    assert result.gaps == ("empty_result",)
    raw["Messages"] = [{"Code": "PartialData", "Value": "private message"}]
    assert replay(request(), RecordedTape((Exchange(call, raw),))).gaps == ("partial_results",)


def test_duplicate_pages_do_not_exhaust_result_budget() -> None:
    scope = request(result_limit=2)
    call = compile_request(scope)
    first = response() | {"NextToken": "opaque"}
    second = response()
    second["MetricDataResults"][0]["Values"].append(4)
    second["MetricDataResults"][0]["Timestamps"].append(datetime.fromtimestamp(START + 60, UTC))
    next_call = type(call)(call.service, call.method, call.parameters | {"NextToken": "opaque"})
    result = replay(scope, RecordedTape((Exchange(call, first), Exchange(next_call, second))))
    assert len(result.observations) == 2 and not result.gaps


def test_payload_node_and_byte_budgets() -> None:
    for raw in (
        [list(range(1000)) for _ in range(11)],
        {str(index): "x" * 2000 for index in range(600)},
        {1: "value"},
    ):
        with pytest.raises(CollectionError, match="unsupported_payload"):
            check_payload(raw)


def test_doctor_missing_profile_invalid_region_and_override() -> None:
    for raw, environment in (
        (CONFIG.replace(b"profile operator", b"profile other"), {}),
        (CONFIG.replace(b"sso_region = eu-central-1", b"sso_region = arbitrary"), {}),
        (CONFIG, {"AWS_REGION": "us-east-1"}),
    ):
        assert not inspect_config(raw, REQUIREMENT, environment).configuration_valid


def test_doctor_refuses_directories_and_missing_files_without_disclosure(tmp_path: Path) -> None:
    for path in (tmp_path, tmp_path / "missing"):
        result = CliRunner().invoke(
            app,
            [
                "doctor",
                "--config",
                str(path),
                "--profile",
                "operator",
                "--account",
                "000000000000",
                "--region",
                REGION,
                "--role",
                "Collector",
            ],
        )
        assert result.exit_code == 2
        assert json.loads(result.stdout)["checks"] == ["configuration_unavailable"]
        assert str(path) not in result.stdout
