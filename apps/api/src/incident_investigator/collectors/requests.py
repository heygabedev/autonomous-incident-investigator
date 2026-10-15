"""Deterministic AWS request templates; no caller-supplied method, endpoint or query."""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from incident_investigator.collectors.contracts import CollectionRequest
from incident_investigator.security.policy import ActionRequest


@dataclass(frozen=True)
class Call:
    service: str
    method: str
    parameters: dict[str, Any] = field(repr=False)


OPERATIONS = {
    "lambda_errors_v1": ("cloudwatch", "get_metric_data"),
    "ecs_cpu_v1": ("cloudwatch", "get_metric_data"),
    "dynamodb_throttles_v1": ("cloudwatch", "get_metric_data"),
    "structured_logs_v1": ("logs", "start_query"),
    "ecs_service_v1": ("ecs", "describe_services"),
    "lambda_configuration_v1": ("lambda", "get_function_configuration"),
    "dynamodb_table_v1": ("dynamodb", "describe_table"),
    "alb_target_health_v1": ("elbv2", "describe_target_health"),
}
METRICS = {
    "lambda_errors_v1": ("AWS/Lambda", "Errors", "Sum", "Count"),
    "ecs_cpu_v1": ("AWS/ECS", "CPUUtilization", "Average", "Percent"),
    "dynamodb_throttles_v1": ("AWS/DynamoDB", "WriteThrottleEvents", "Sum", "Count"),
}


def compile_request(request: CollectionRequest) -> Call:
    request = CollectionRequest.model_validate_json(request.model_dump_json())
    service, method = OPERATIONS[request.template]
    name = request.resource.split(":", 5)[5]
    parameters: dict[str, Any]
    if request.template in METRICS:
        namespace, metric, statistic, unit = METRICS[request.template]
        if namespace == "AWS/ECS":
            _, cluster, target = name.split("/")
            dimensions = [
                {"Name": "ClusterName", "Value": cluster},
                {"Name": "ServiceName", "Value": target},
            ]
        elif namespace == "AWS/Lambda":
            dimensions = [{"Name": "FunctionName", "Value": name.split(":", 1)[1]}]
        else:
            dimensions = [{"Name": "TableName", "Value": name.split("/", 1)[1]}]
        parameters = {
            "MetricDataQueries": [
                {
                    "Id": "m1",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": namespace,
                            "MetricName": metric,
                            "Dimensions": dimensions,
                        },
                        "Period": 60,
                        "Stat": statistic,
                        "Unit": unit,
                    },
                    "ReturnData": True,
                }
            ],
            "StartTime": datetime.fromtimestamp(request.window_start, UTC),
            "EndTime": datetime.fromtimestamp(request.window_end, UTC),
            "MaxDatapoints": request.result_limit,
            "ScanBy": "TimestampAscending",
        }
    elif request.template == "structured_logs_v1":
        parameters = {
            "logGroupIdentifiers": [request.resource],
            "startTime": request.window_start,
            "endTime": request.window_end,
            "limit": request.result_limit,
            "queryString": "fields status, error_code | filter status in "
            '["error", "failed", "throttled", "timeout"] '
            "| stats count(*) as occurrences by status, error_code | sort occurrences desc",
        }
    elif request.template == "ecs_service_v1":
        _, cluster, _ = name.split("/")
        parameters = {
            "cluster": f"arn:aws:ecs:{request.region}:{request.account_id}:cluster/{cluster}",
            "services": [request.resource],
        }
    elif request.template == "lambda_configuration_v1":
        parameters = {"FunctionName": request.resource}
    elif request.template == "dynamodb_table_v1":
        parameters = {"TableName": request.resource}
    else:
        parameters = {"TargetGroupArn": request.resource}
    return Call(service, method, parameters)


def query_call(query_id: str, *, stop: bool = False) -> Call:
    if not re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", query_id):
        raise ValueError("invalid_query_id")
    return Call("logs", "stop_query" if stop else "get_query_results", {"queryId": query_id})


def authorization_request(request: CollectionRequest) -> ActionRequest:
    call = compile_request(request)
    return ActionRequest(
        operation=f"{call.service}.{call.method}",
        account_id=request.account_id,
        region=request.region,
        resource=request.resource,
        template=request.template,
        result_limit=request.result_limit,
        # No zero-cost authorization is issued for a potentially billable live query.
        cost_microdollars=500_000,
    )
