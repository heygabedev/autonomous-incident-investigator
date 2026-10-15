"""Allowlisted extraction only. AWS response text, environment and labels stay transient."""

import math
from datetime import datetime
from typing import Any, cast

from incident_investigator.collectors.contracts import (
    CollectedObservation,
    CollectionError,
    CollectionRequest,
    Gap,
)
from incident_investigator.collectors.requests import METRICS, OPERATIONS
from incident_investigator.security.evidence import RawEvidence, sanitize


def check_payload(value: object) -> None:
    budget = [0, 0]

    def visit(item: object, depth: int) -> None:
        budget[1] += 1
        if depth > 12 or budget[1] > 10_000:
            raise CollectionError("unsupported_payload")
        if isinstance(item, str):
            if len(item) > 1_048_576:
                raise CollectionError("unsupported_payload")
            budget[0] += len(item.encode("utf-8"))
        elif type(item) in (int, float):
            number = cast(int | float, item)
            if abs(number) > 2**53 or not math.isfinite(number):
                raise CollectionError("unsupported_payload")
            budget[0] += 16
        elif item is None or type(item) is bool or isinstance(item, datetime):
            budget[0] += 32
        elif isinstance(item, dict):
            if len(item) > 1000 or any(type(key) is not str for key in item):
                raise CollectionError("unsupported_payload")
            for key, child in item.items():
                visit(key, depth + 1)
                visit(child, depth + 1)
        elif isinstance(item, (tuple, list)):
            if len(item) > 1000:
                raise CollectionError("unsupported_payload")
            for child in item:
                visit(child, depth + 1)
        else:
            raise CollectionError("unsupported_payload")
        if budget[0] > 1_048_576:
            raise CollectionError("unsupported_payload")

    visit(value, 0)


def _number(value: object) -> int | float:
    if type(value) not in (int, float):
        raise CollectionError("unsupported_payload")
    number = cast(int | float, value)
    if abs(number) > 2**53 or not math.isfinite(number) or number < 0:
        raise CollectionError("unsupported_payload")
    return number


def normalize(
    request: CollectionRequest, payload: dict[str, Any]
) -> tuple[list[CollectedObservation], list[Gap]]:
    request = CollectionRequest.model_validate_json(request.model_dump_json())
    check_payload(payload)
    records: list[CollectedObservation] = []
    gaps: list[Gap] = []
    operation = ".".join(OPERATIONS[request.template])

    def emit(fields: dict[str, object], timestamp: int | None = None) -> None:
        # Hash sample time too: equal readings at different times remain distinct.
        scope = f".w{request.window_start}-{request.window_end}"
        fields = {
            "operation": operation + scope + (f".t{timestamp}" if timestamp is not None else ""),
            **fields,
        }
        result = sanitize(
            RawEvidence(request.account_id, request.region, request.resource, fields),
            request.account_id,
            request.region,
            (request.resource,),
        )
        if result.evidence is None:
            raise CollectionError("unsupported_payload")
        records.append(
            CollectedObservation(
                evidence=result.evidence,
                occurred_at=timestamp,
                temporal_scope="sample"
                if timestamp is not None
                else (
                    "window_aggregate" if request.template == "structured_logs_v1" else "snapshot"
                ),
            )
        )

    def status(value: object, allowed: tuple[str, ...]) -> str:
        if not isinstance(value, str) or value not in allowed:
            raise CollectionError("unsupported_payload")
        return value

    if request.template in METRICS:
        series = payload["MetricDataResults"]
        if not isinstance(series, list) or len(series) != 1 or series[0]["Id"] != "m1":
            raise CollectionError("scope_mismatch")
        item = series[0]
        state = status(
            item["StatusCode"], ("Complete", "PartialData", "InternalError", "Forbidden")
        )
        if state != "Complete":
            gaps.append("permission_denied" if state == "Forbidden" else "partial_results")
        if state in ("Forbidden", "InternalError"):
            return [], gaps
        values, times = item["Values"], item["Timestamps"]
        if len(values) != len(times):
            raise CollectionError("unsupported_payload")
        for value, moment in zip(values, times, strict=True):
            if not isinstance(moment, datetime) or moment.tzinfo is None:
                raise CollectionError("unsupported_payload")
            timestamp = int(moment.timestamp())
            if not request.window_start <= timestamp < request.window_end:
                raise CollectionError("scope_mismatch")
            emit(
                {
                    "metric_name": METRICS[request.template][1],
                    "value": _number(value),
                    "unit": METRICS[request.template][3],
                },
                timestamp,
            )
        if payload.get("Messages") or item.get("Messages"):
            gaps.append("partial_results")
    elif request.template == "ecs_service_v1":
        if payload.get("failures"):
            return [], ["unavailable"]
        services = payload["services"]
        if len(services) != 1 or services[0]["serviceArn"] != request.resource:
            raise CollectionError("scope_mismatch")
        item = services[0]
        cluster = request.resource.rsplit(":", 1)[0] + ":cluster/" + request.resource.split("/")[-2]
        if item["clusterArn"] != cluster:
            raise CollectionError("scope_mismatch")
        state = status(item["status"], ("ACTIVE", "DRAINING", "INACTIVE"))
        emit({"status": state})
        for name in ("desiredCount", "runningCount", "pendingCount"):
            emit({"metric_name": name, "value": _number(item[name]), "unit": "Count"})
        if item.get("events") or item.get("deployments"):
            gaps.append("restricted_fields_omitted")
    elif request.template == "lambda_configuration_v1":
        if payload["FunctionArn"] != request.resource:
            raise CollectionError("scope_mismatch")
        emit({"status": status(payload["State"], ("Pending", "Active", "Inactive", "Failed"))})
        emit({"metric_name": "Timeout", "value": _number(payload["Timeout"]), "unit": "Seconds"})
        emit(
            {
                "metric_name": "MemorySize",
                "value": _number(payload["MemorySize"]),
                "unit": "Megabytes",
            }
        )
        if payload.get("Environment") or payload.get("StateReason") or payload.get("Description"):
            gaps.append("restricted_fields_omitted")
    elif request.template == "dynamodb_table_v1":
        item = payload["Table"]
        if item["TableArn"] != request.resource:
            raise CollectionError("scope_mismatch")
        emit(
            {
                "status": status(
                    item["TableStatus"],
                    (
                        "CREATING",
                        "UPDATING",
                        "DELETING",
                        "ACTIVE",
                        "INACCESSIBLE_ENCRYPTION_CREDENTIALS",
                        "ARCHIVING",
                        "ARCHIVED",
                        "REPLICATION_NOT_AUTHORIZED",
                    ),
                )
            }
        )
        for name in ("ItemCount", "TableSizeBytes"):
            emit(
                {
                    "metric_name": name,
                    "value": _number(item[name]),
                    "unit": "Bytes" if name == "TableSizeBytes" else "Count",
                }
            )
    elif request.template == "alb_target_health_v1":
        counts: dict[str, int] = {}
        for item in payload["TargetHealthDescriptions"]:
            health = status(
                item["TargetHealth"]["State"],
                (
                    "initial",
                    "healthy",
                    "unhealthy",
                    "unhealthy.draining",
                    "unused",
                    "draining",
                    "unavailable",
                ),
            )
            counts[health] = counts.get(health, 0) + 1
        for health, count in sorted(counts.items()):
            emit({"status": health, "metric_name": "TargetCount", "value": count, "unit": "Count"})
        # Target addresses, health-check descriptions and ports are deliberately not retained.
        if counts:
            gaps.append("restricted_fields_omitted")
    else:
        if len(payload["results"]) >= request.result_limit:
            gaps.append("result_limit")
        for row in payload["results"]:
            fields = {item["field"]: item["value"] for item in row}
            if len(fields) != len(row):
                raise CollectionError("unsupported_payload")
            if set(fields) - {"status", "error_code", "occurrences"}:
                gaps.append("restricted_fields_omitted")
            state = status(fields["status"], ("error", "failed", "throttled", "timeout"))
            code = status(
                fields.get("error_code", ""),
                (
                    "",
                    "AccessDenied",
                    "AccessDeniedException",
                    "ThrottlingException",
                    "TimeoutError",
                    "ResourceNotFoundException",
                    "ProvisionedThroughputExceededException",
                ),
            )
            count = fields["occurrences"]
            if (
                not isinstance(count, str)
                or not count.isascii()
                or not count.isdigit()
                or len(count) > 12
            ):
                raise CollectionError("unsupported_payload")
            log_fields: dict[str, object] = {
                "status": state,
                "metric_name": "Occurrences",
                "value": int(count),
                "unit": "Count",
            }
            if code:
                log_fields["error_code"] = code
            emit(log_fields)
    return records, gaps
