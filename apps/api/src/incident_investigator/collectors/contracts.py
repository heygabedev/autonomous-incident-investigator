import re
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from incident_investigator.evaluation.models import Contract, Digest, Identifier
from incident_investigator.security.evidence import SanitizedEvidence, redact
from incident_investigator.security.policy import Account, Resource

Template = Literal[
    "lambda_errors_v1",
    "ecs_cpu_v1",
    "dynamodb_throttles_v1",
    "structured_logs_v1",
    "ecs_service_v1",
    "lambda_configuration_v1",
    "dynamodb_table_v1",
    "alb_target_health_v1",
]
Gap = Literal[
    "permission_denied",
    "unavailable",
    "throttled",
    "unsupported_payload",
    "scope_mismatch",
    "partial_results",
    "result_limit",
    "call_limit",
    "deadline",
    "pagination_cycle",
    "restricted_fields_omitted",
    "query_failed",
    "empty_result",
]
Epoch = Annotated[int, Field(ge=0, le=4_102_444_800)]

# Only explicit commercial-partition targets are supported in this slice.
TARGETS: dict[str, tuple[str, str]] = {
    "lambda_errors_v1": ("lambda", r"function:[A-Za-z0-9_-]{1,64}"),
    "lambda_configuration_v1": ("lambda", r"function:[A-Za-z0-9_-]{1,64}"),
    "ecs_cpu_v1": ("ecs", r"service/[A-Za-z0-9_-]{1,255}/[A-Za-z0-9_-]{1,255}"),
    "ecs_service_v1": ("ecs", r"service/[A-Za-z0-9_-]{1,255}/[A-Za-z0-9_-]{1,255}"),
    "dynamodb_throttles_v1": ("dynamodb", r"table/[A-Za-z0-9_.-]{3,255}"),
    "dynamodb_table_v1": ("dynamodb", r"table/[A-Za-z0-9_.-]{3,255}"),
    "structured_logs_v1": ("logs", r"log-group:[A-Za-z0-9/_.-]{1,400}"),
    "alb_target_health_v1": (
        "elasticloadbalancing",
        r"targetgroup/[A-Za-z0-9-]{1,32}/[0-9a-f]{16}",
    ),
}


class CollectionRequest(Contract):
    template: Template
    account_id: Account
    region: Identifier
    resource: Resource
    window_start: Epoch
    window_end: Epoch
    result_limit: Annotated[int, Field(ge=1, le=100)] = 100
    max_calls: Annotated[int, Field(ge=3, le=12)] = 8
    max_pages: Annotated[int, Field(ge=1, le=3)] = 3
    timeout_ms: Annotated[int, Field(ge=100, le=30_000)] = 10_000

    @model_validator(mode="after")
    def scope(self) -> Self:
        service, pattern = TARGETS[self.template]
        if not re.fullmatch(r"[a-z]{2}-[a-z]+-\d", self.region):
            raise ValueError("unsupported_region")
        prefix = f"arn:aws:{service}:{self.region}:{self.account_id}:"
        if not self.resource.startswith(prefix) or not re.fullmatch(
            pattern, self.resource[len(prefix) :]
        ):
            raise ValueError("resource_scope_mismatch")
        if redact(self.resource) != self.resource:
            raise ValueError("unsafe_resource_name")
        if not 0 < self.window_end - self.window_start <= 3600:
            raise ValueError("window_must_be_between_one_second_and_one_hour")
        return self


class CollectedObservation(Contract):
    evidence: SanitizedEvidence
    occurred_at: Epoch | None = None
    temporal_scope: Literal["snapshot", "sample", "window_aggregate"] = "snapshot"


class CollectionResult(Contract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    source: Literal["recorded_aws_contract"] = "recorded_aws_contract"
    request_digest: Digest
    template: Template
    observations: Annotated[tuple[CollectedObservation, ...], Field(max_length=100)]
    gaps: Annotated[tuple[Gap, ...], Field(max_length=16)]
    calls: Annotated[int, Field(ge=0, le=12)]
    elapsed_ms: Annotated[int, Field(ge=0)]


class CollectionError(Exception):
    def __init__(self, reason: Gap) -> None:
        super().__init__(reason)
        self.reason = reason
