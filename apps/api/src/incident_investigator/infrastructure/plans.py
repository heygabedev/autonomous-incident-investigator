"""Conservative recovery checks, not an IAM analyzer or deployment approval.

Input is the bounded JSON output of Terraform show, never an executable plan.
Unknown encryption identifiers and new policy documents need separate review.
Existing policy changes are blocked until a reviewed migration path exists.
"""

import re
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict

from incident_investigator.evaluation.canonical import JSONValue, content_digest, parse_json

TERRAFORM_VERSION = "1.16.6"
AWS_PROVIDER = "registry.terraform.io/hashicorp/aws"
type Object = dict[str, JSONValue]
type Path = tuple[str | int, ...]


class PlanCheck(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: Literal["passed", "blocked", "review_required"]
    deployment_authorized: Literal[False] = False
    plan_digest: str | None = None
    reasons: tuple[str, ...]
    resources_checked: int = 0


@dataclass(frozen=True)
class Rule:
    path: Path
    expected: bool | int | str | None = None
    minimum: int | None = None

    def matches(self, value: JSONValue) -> bool:
        if self.minimum is not None:
            return type(value) is int and value >= self.minimum
        if self.expected is None:
            return isinstance(value, str) and bool(
                re.fullmatch(r"arn:aws:kms:[a-z0-9-]+:\d{12}:key/[a-f0-9-]{36}", value)
            )
        return type(value) is type(self.expected) and value == self.expected


RULES: dict[str, tuple[Rule, ...]] = {
    "aws_s3_bucket": (Rule(("force_destroy",), False),),
    "aws_s3_bucket_public_access_block": tuple(
        Rule((field,), True)
        for field in (
            "block_public_acls",
            "block_public_policy",
            "ignore_public_acls",
            "restrict_public_buckets",
        )
    ),
    "aws_s3_bucket_ownership_controls": (
        Rule(("rule", 0, "object_ownership"), "BucketOwnerEnforced"),
    ),
    "aws_s3_bucket_versioning": (Rule(("versioning_configuration", 0, "status"), "Enabled"),),
    "aws_s3_bucket_server_side_encryption_configuration": (
        Rule(("rule", 0, "apply_server_side_encryption_by_default", 0, "sse_algorithm"), "aws:kms"),
        Rule(("rule", 0, "apply_server_side_encryption_by_default", 0, "kms_master_key_id")),
    ),
    "aws_dynamodb_table": (
        Rule(("deletion_protection_enabled",), True),
        Rule(("point_in_time_recovery", 0, "enabled"), True),
        Rule(("point_in_time_recovery", 0, "recovery_period_in_days"), minimum=35),
        Rule(("server_side_encryption", 0, "enabled"), True),
        Rule(("server_side_encryption", 0, "kms_key_arn")),
    ),
    "aws_kms_key": (
        Rule(("enable_key_rotation",), True),
        Rule(("deletion_window_in_days",), 30),
    ),
    "aws_sqs_queue": (
        Rule(("message_retention_seconds",), 1_209_600),
        Rule(("kms_master_key_id",)),
    ),
    "aws_cloudwatch_log_group": (
        Rule(("retention_in_days",), minimum=90),
        Rule(("kms_key_id",)),
    ),
    "aws_cloudwatch_event_rule": (Rule(("state",), "DISABLED"),),
}

# Any mutation of these resources, even a create, needs additional review.
REVIEW_TYPES = {
    "aws_iam_policy",
    "aws_iam_role",
    "aws_iam_role_policy_attachment",
    "aws_kms_alias",
    "aws_s3_bucket_policy",
    "aws_s3_bucket_lifecycle_configuration",
    "aws_sqs_queue_policy",
    "aws_sqs_queue_redrive_policy",
    "aws_sqs_queue_redrive_allow_policy",
    "aws_cloudwatch_event_target",
    "aws_cloudwatch_metric_alarm",
}


def _object(value: JSONValue) -> Object:
    if not isinstance(value, dict):
        raise ValueError("invalid_plan")
    return value


def _at(value: JSONValue, path: Path) -> JSONValue:
    for key in path:
        if isinstance(key, int):
            # These provider blocks must be singletons, not partially checked arrays.
            if not isinstance(value, list) or len(value) != 1:
                return None
            value = value[key]
        else:
            if not isinstance(value, dict):
                return None
            value = value.get(key)
    return value


def _unknown(value: JSONValue, path: Path) -> bool:
    if value is True:
        return True
    if not path:
        return value is not None and value is not False and value != {}
    head, *tail = path
    if isinstance(head, int) and isinstance(value, list) and len(value) == 1:
        return _unknown(value[head], tuple(tail))
    if isinstance(head, str) and isinstance(value, dict):
        return _unknown(value.get(head), tuple(tail))
    return False


def _resource(item: Object, denied: set[str], review: set[str]) -> None:
    change = _object(item.get("change"))
    if change.get("importing"):
        denied.add("state_import_requires_review")
    actions = change.get("actions")
    if not isinstance(actions, list) or not all(isinstance(a, str) for a in actions):
        raise ValueError("invalid_plan")
    if any(a in ("delete", "forget") for a in actions):
        denied.add("destructive_change")
        return
    if actions not in (["no-op"], ["create"], ["update"], ["read"]):
        denied.add("unsupported_action")
        return
    if item.get("provider_name") != AWS_PROVIDER:
        denied.add("unsupported_provider")
        return
    if item.get("mode") == "data":
        if actions not in (["read"], ["no-op"]) or item.get("type") != "aws_caller_identity":
            denied.add("unsupported_data_source")
        return
    if item.get("mode") != "managed" or actions == ["read"]:
        raise ValueError("invalid_plan")
    kind = item.get("type")
    if not isinstance(kind, str) or kind not in RULES.keys() | REVIEW_TYPES:
        denied.add("unsupported_resource")
        return
    after = _object(change.get("after"))
    unknown = change.get("after_unknown", {})
    if not isinstance(unknown, dict):
        raise ValueError("invalid_plan")
    for rule in RULES.get(kind, ()):
        if _unknown(unknown, rule.path):
            (review if actions == ["create"] else denied).add("unresolved_recovery_control")
        elif not rule.matches(_at(after, rule.path)):
            denied.add("unsafe_recovery_control")
    if kind == "aws_dynamodb_table" and after.get("ttl") not in (None, []):
        denied.add("ttl_requires_retention_review")
    if actions != ["no-op"]:
        if kind in REVIEW_TYPES or kind == "aws_kms_key":
            (review if actions == ["create"] else denied).add("security_change_requires_review")
        # Even apparently safe updates may remove attributes outside the recovery checks.
        elif actions == ["update"]:
            denied.add("update_requires_migration_review")


def check_plan(raw: bytes) -> PlanCheck:
    """Return fixed reason codes only. Plan contents can include plaintext secrets."""
    denied: set[str] = set()
    review: set[str] = set()
    try:
        plan = _object(parse_json(raw))
        digest = content_digest(plan)
        version = plan.get("format_version")
        if not isinstance(version, str) or not re.fullmatch(r"1\.\d+", version):
            denied.add("unsupported_plan_format")
        if plan.get("terraform_version") != TERRAFORM_VERSION:
            denied.add("unsupported_terraform_version")
        if plan.get("complete") is not True or plan.get("errored") is not False:
            denied.add("incomplete_or_failed_plan")
        if type(plan.get("applyable")) is not bool:
            raise ValueError("invalid_plan")
        if plan.get("resource_drift") or plan.get("deferred_changes"):
            denied.add("drift_or_deferral_requires_review")
        if plan.get("action_invocations"):
            denied.add("external_action_requires_review")
        checks = plan.get("checks", [])
        if not isinstance(checks, list) or any(
            _object(check).get("status") != "pass" for check in checks
        ):
            denied.add("unverified_plan_checks")
        items = plan.get("resource_changes", [])
        if not isinstance(items, list) or len(items) > 500:
            raise ValueError("invalid_plan")
        seen: set[str] = set()
        for item in items:
            resource = _object(item)
            address = resource.get("address")
            if not isinstance(address, str) or not address or address in seen:
                raise ValueError("invalid_plan")
            seen.add(address)
            if resource.get("deposed") or resource.get("previous_address"):
                denied.add("state_move_requires_review")
            _resource(resource, denied, review)
        if plan["applyable"] is False and any(
            _object(_object(item).get("change")).get("actions") != ["no-op"] for item in items
        ):
            denied.add("nonapplyable_changes")
        return PlanCheck(
            status="blocked" if denied else "review_required" if review else "passed",
            plan_digest=digest,
            reasons=tuple(sorted(denied | review)),
            resources_checked=len(items),
        )
    except (ValueError, TypeError, RecursionError):
        return PlanCheck(status="blocked", reasons=("invalid_plan",))
