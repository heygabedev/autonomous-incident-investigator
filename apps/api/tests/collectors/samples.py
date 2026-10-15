from datetime import UTC, datetime
from typing import Any

from incident_investigator.collectors.contracts import CollectionRequest, Template

ACCOUNT = "000000000000"
REGION = "eu-central-1"
START = 1_735_689_600
QUERY = "12345678-1234-1234-1234-123456789012"
TARGETS: dict[Template, str] = {
    "lambda_errors_v1": "lambda:function:checkout",
    "lambda_configuration_v1": "lambda:function:checkout",
    "ecs_cpu_v1": "ecs:service/production/checkout",
    "ecs_service_v1": "ecs:service/production/checkout",
    "dynamodb_throttles_v1": "dynamodb:table/checkout",
    "dynamodb_table_v1": "dynamodb:table/checkout",
    "alb_target_health_v1": "elasticloadbalancing:targetgroup/checkout/0123456789abcdef",
    "structured_logs_v1": "logs:log-group:/aws/lambda/checkout",
}


def request(template: Template = "lambda_errors_v1", **changes: Any) -> CollectionRequest:
    service, name = TARGETS[template].split(":", 1)
    return CollectionRequest.model_validate(
        {
            "template": template,
            "account_id": ACCOUNT,
            "region": REGION,
            "resource": f"arn:aws:{service}:{REGION}:{ACCOUNT}:{name}",
            "window_start": START,
            "window_end": START + 600,
            **changes,
        }
    )


def response(template: Template = "lambda_errors_v1") -> dict[str, Any]:
    scope = request(template)
    if template in ("lambda_errors_v1", "ecs_cpu_v1", "dynamodb_throttles_v1"):
        return {
            "MetricDataResults": [
                {
                    "Id": "m1",
                    "StatusCode": "Complete",
                    "Label": "private label",
                    "Timestamps": [datetime.fromtimestamp(START, UTC)],
                    "Values": [3.0],
                }
            ]
        }
    if template == "ecs_service_v1":
        return {
            "services": [
                {
                    "serviceArn": scope.resource,
                    "clusterArn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/production",
                    "status": "ACTIVE",
                    "desiredCount": 3,
                    "runningCount": 2,
                    "pendingCount": 1,
                }
            ]
        }
    if template == "lambda_configuration_v1":
        return {
            "FunctionArn": scope.resource,
            "State": "Active",
            "Timeout": 30,
            "MemorySize": 128,
            "Environment": {"Variables": {"PASSWORD": "private-value"}},
            "Description": "private description",
        }
    if template == "dynamodb_table_v1":
        return {
            "Table": {
                "TableArn": scope.resource,
                "TableStatus": "ACTIVE",
                "ItemCount": 30,
                "TableSizeBytes": 128,
            }
        }
    if template == "alb_target_health_v1":
        return {
            "TargetHealthDescriptions": [
                {
                    "Target": {"Id": "10.0.0.1", "Port": 80},
                    "TargetHealth": {"State": "unhealthy", "Description": "private description"},
                }
            ]
        }
    return {
        "status": "Complete",
        "results": [
            [
                {"field": "status", "value": "error"},
                {"field": "error_code", "value": "AccessDeniedException"},
                {"field": "occurrences", "value": "2"},
            ]
        ],
    }
