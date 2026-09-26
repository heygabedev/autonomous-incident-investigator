"""Deny-by-default authorization. No live collector is enabled by this module."""

from collections.abc import Callable
from typing import Annotated, Literal

from pydantic import Field, StringConstraints

from incident_investigator.evaluation.models import Contract, Identifier

Account = Annotated[str, StringConstraints(pattern=r"^[0-9]{12}$")]
Resource = Annotated[str, StringConstraints(min_length=1, max_length=512)]
Feature = Literal["collection", "model", "history", "publication"]


class SecurityContext(Contract):
    actor_id: Identifier
    candidate_id: Identifier
    policy_id: Identifier
    account_id: Account
    region: Identifier


class ActionRequest(Contract):
    operation: Identifier
    account_id: Account
    region: Identifier
    resource: Resource
    template: Identifier
    result_limit: Annotated[int, Field(ge=1, le=1000)]
    cost_microdollars: Annotated[int, Field(ge=0, le=500_000)]


class SecurityPolicy(Contract):
    id: Identifier
    revision: Annotated[int, Field(ge=1)]
    expires_at: Annotated[int, Field(ge=0)]
    account_id: Account
    region: Identifier
    resources: Annotated[tuple[Resource, ...], Field(max_length=1000)]
    operations: Annotated[tuple[Identifier, ...], Field(max_length=100)]
    templates: Annotated[tuple[Identifier, ...], Field(max_length=100)]
    result_limit: Annotated[int, Field(ge=0, le=1000)]
    remaining_microdollars: Annotated[int, Field(ge=0, le=500_000)]
    disabled_features: Annotated[tuple[Feature, ...], Field(max_length=4)] = ()
    revoked_candidates: Annotated[tuple[Identifier, ...], Field(max_length=1000)] = ()
    safe_mode: bool = False


class AuthorizationDecision(Contract):
    allowed: bool
    reason: Identifier
    policy_revision: int | None


# A declaration is not activation: all live operations remain disabled until
# their adapter-specific IAM, scope, and retry gates have been implemented.
OPERATIONS: dict[str, tuple[Feature, bool]] = {
    "fixture.read": ("collection", False),
    "cloudwatch.get_metric_data": ("collection", True),
    "logs.start_query": ("collection", True),
    "bedrock.converse": ("model", True),
    "history.read": ("history", False),
    "report.publish": ("publication", False),
}


def authorize(
    context: SecurityContext,
    request: ActionRequest,
    pinned: SecurityPolicy,
    current: SecurityPolicy | None,
    now: int,
) -> AuthorizationDecision:
    revision = current.revision if current else None

    def deny(reason: str) -> AuthorizationDecision:
        return AuthorizationDecision(allowed=False, reason=reason, policy_revision=revision)

    if current is None:
        return deny("policy_unavailable")
    if context.policy_id != pinned.id or current.id != pinned.id:
        return deny("policy_mismatch")
    if current.revision < pinned.revision:
        return deny("policy_regression")
    if now >= min(pinned.expires_at, current.expires_at):
        return deny("policy_expired")
    operation = OPERATIONS.get(request.operation)
    if operation is None:
        return deny("operation_unregistered")
    feature, live = operation
    if live:
        return deny("live_adapter_disabled")
    for policy in (pinned, current):
        if context.candidate_id in policy.revoked_candidates:
            return deny("candidate_revoked")
        if policy.safe_mode and request.operation != "fixture.read":
            return deny("contained")
        if feature in policy.disabled_features and request.operation != "fixture.read":
            return deny("feature_disabled")
        if request.account_id != policy.account_id or context.account_id != policy.account_id:
            return deny("account_denied")
        if request.region != policy.region or context.region != policy.region:
            return deny("region_denied")
        if request.resource not in policy.resources:
            return deny("resource_denied")
        if request.operation not in policy.operations:
            return deny("operation_denied")
        if request.template not in policy.templates:
            return deny("template_denied")
        if request.result_limit > policy.result_limit:
            return deny("result_limit")
        if request.cost_microdollars > policy.remaining_microdollars:
            return deny("budget_exceeded")
    return AuthorizationDecision(allowed=True, reason="allowed", policy_revision=revision)


class OperationDenied(Exception):
    pass


class Broker:
    def __init__(
        self,
        current_policy: Callable[[], SecurityPolicy | None],
        record_intent: Callable[[SecurityContext, ActionRequest, AuthorizationDecision], None],
        clock: Callable[[], int],
    ) -> None:
        self.current_policy = current_policy
        self.record_intent = record_intent
        self.clock = clock

    def dispatch[T](
        self,
        context: SecurityContext,
        request: ActionRequest,
        pinned: SecurityPolicy,
        handler: Callable[[ActionRequest], T],
    ) -> T:
        # Revalidate internal objects too: model_construct/copy can bypass Pydantic.
        context = SecurityContext.model_validate_json(context.model_dump_json())
        request = ActionRequest.model_validate_json(request.model_dump_json())
        pinned = SecurityPolicy.model_validate_json(pinned.model_dump_json())
        try:
            current = self.current_policy()
            if current is not None:
                current = SecurityPolicy.model_validate_json(current.model_dump_json())
        except Exception:
            current = None
        decision = authorize(context, request, pinned, current, self.clock())
        try:
            self.record_intent(context, request, decision)
        except Exception:
            raise OperationDenied("audit_unavailable") from None
        if not decision.allowed:
            raise OperationDenied(decision.reason)
        # An intent is not a lease over future governance: refuse a changed view.
        try:
            latest = self.current_policy()
        except Exception:
            raise OperationDenied("policy_unavailable") from None
        if latest != current:
            raise OperationDenied("policy_changed")
        if not authorize(context, request, pinned, latest, self.clock()).allowed:
            raise OperationDenied("policy_changed")
        return handler(request)
