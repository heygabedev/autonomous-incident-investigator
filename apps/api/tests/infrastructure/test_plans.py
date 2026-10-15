import json
from copy import deepcopy
from pathlib import Path

import pytest
from incident_investigator.evaluation.canonical import MAX_BYTES
from incident_investigator.infrastructure.plans import AWS_PROVIDER, RULES, check_plan
from incident_investigator.security.cli import app
from typer.testing import CliRunner


def resource(kind="aws_s3_bucket", after=None, actions=None):
    return {
        "address": f"{kind}.test",
        "mode": "managed",
        "type": kind,
        "provider_name": AWS_PROVIDER,
        "change": {
            "actions": ["create"] if actions is None else actions,
            "after": {"force_destroy": False} if after is None else after,
            "after_unknown": {},
        },
    }


def plan(*items):
    return {
        "format_version": "1.2",
        "terraform_version": "1.16.6",
        "complete": True,
        "applyable": True,
        "errored": False,
        "resource_changes": list(items),
    }


def check(value):
    return check_plan(json.dumps(value).encode())


def safe_values(rules):
    result = {}
    for rule in rules:
        node = result
        for index, key in enumerate(rule.path[:-1]):
            if isinstance(key, int):
                node = node[key]
            else:
                node = node.setdefault(key, [{}] if rule.path[index + 1] == 0 else {})
        node[rule.path[-1]] = (
            rule.minimum
            if rule.minimum is not None
            else rule.expected
            if rule.expected is not None
            else "arn:aws:kms:eu-central-1:111122223333:key/00000000-0000-0000-0000-000000000001"
        )
    return result


def set_at(value, path, replacement):
    for part in path[:-1]:
        value = value[part]
    value[path[-1]] = replacement


@pytest.mark.parametrize("kind,rules", RULES.items())
def test_each_recovery_rule_accepts_safe_values_and_denies_weakening(kind, rules):
    values = safe_values(rules)
    result = check(plan(resource(kind, values)))
    assert result.status == ("review_required" if kind == "aws_kms_key" else "passed")
    assert not result.deployment_authorized
    for rule in rules:
        unsafe = deepcopy(values)
        set_at(unsafe, rule.path, None)
        result = check(plan(resource(kind, unsafe)))
        assert result.status == "blocked"
        assert "unsafe_recovery_control" in result.reasons


@pytest.mark.parametrize(
    "actions", [["delete"], ["create", "delete"], ["delete", "create"], ["forget"]]
)
def test_deletions_denied_even_for_resources_removed_from_configuration(actions):
    result = check(plan(resource("aws_unknown_old_resource", {}, actions)))
    assert result.status == "blocked"
    assert "destructive_change" in result.reasons


@pytest.mark.parametrize("actions", [[], ["create", "update"], ["invented"], [1], "delete", None])
def test_unknown_or_malformed_actions_fail_closed(actions):
    item = resource()
    item["change"]["actions"] = actions
    assert check(plan(item)).status == "blocked"


@pytest.mark.parametrize(
    "key,value",
    [
        ("format_version", "2.0"),
        ("format_version", None),
        ("terraform_version", "1.0.0"),
        ("complete", False),
        ("complete", 1),
        ("errored", True),
        ("applyable", "true"),
        ("resource_drift", [{}]),
        ("deferred_changes", [{}]),
        ("checks", [{"status": "unknown"}]),
        ("checks", [{"status": "fail"}]),
        ("checks", None),
        ("resource_changes", {}),
        ("resource_changes", [None]),
    ],
)
def test_bad_metadata_is_blocked(key, value):
    source = plan(resource())
    source[key] = value
    assert check(source).status == "blocked"


@pytest.mark.parametrize("field", ["complete", "errored", "applyable", "terraform_version"])
def test_required_metadata_cannot_be_omitted(field):
    source = plan(resource())
    del source[field]
    assert check(source).status == "blocked"


def test_completed_noop_and_passed_checks():
    source = plan(resource(actions=["no-op"]))
    source.update(applyable=False, checks=[{"status": "pass"}])
    result = check(source)
    assert result.status == "passed"
    assert result.resources_checked == 1
    assert result.plan_digest.startswith("sha256:")
    assert check(source) == result


@pytest.mark.parametrize(
    "raw",
    [
        b"[]",
        b"null",
        b"{",
        b'"secret"',
        b"\xff",
        b'{"complete":true,"complete":false}',
        b" " * (MAX_BYTES + 1),
        b"[" * 100 + b"]" * 100,
    ],
    ids=["array", "null", "truncated", "string", "encoding", "duplicate", "oversize", "deep"],
)
def test_bounded_strict_parser(raw):
    result = check_plan(raw)
    assert result.status == "blocked"
    assert result.plan_digest is None
    assert "secret" not in result.model_dump_json()


@pytest.mark.parametrize(
    "field,value",
    [
        ("provider_name", "registry.terraform.io/other/aws"),
        ("mode", "ephemeral"),
        ("type", "aws_instance"),
        ("address", ""),
        ("address", None),
        ("previous_address", "old.test"),
        ("deposed", "deadbeef"),
    ],
)
def test_unreviewed_resource_metadata(field, value):
    item = resource()
    item[field] = value
    assert check(plan(item)).status == "blocked"


def test_duplicate_addresses_and_bounded_count():
    assert check(plan(resource(), resource())).status == "blocked"
    assert check(plan(*[resource() for _ in range(501)])).status == "blocked"


@pytest.mark.parametrize(
    "kind",
    [
        "aws_iam_role",
        "aws_iam_policy",
        "aws_s3_bucket_policy",
        "aws_s3_bucket_lifecycle_configuration",
        "aws_kms_alias",
        "aws_cloudwatch_event_target",
    ],
)
def test_new_security_resources_require_review_and_updates_are_blocked(kind):
    assert check(plan(resource(kind, {}))).status == "review_required"
    assert check(plan(resource(kind, {}, ["update"]))).status == "blocked"
    assert check(plan(resource(kind, {}, ["no-op"]))).status == "passed"


def test_any_update_requires_migration_review():
    assert check(plan(resource(actions=["update"]))).status == "blocked"


@pytest.mark.parametrize(
    "actions,status", [(["create"], "review_required"), (["update"], "blocked")]
)
@pytest.mark.parametrize("unknown", [True, {"kms_master_key_id": True}])
def test_unknown_key_is_not_silently_approved(actions, status, unknown):
    item = resource("aws_sqs_queue", {"message_retention_seconds": 1_209_600}, actions)
    item["change"]["after_unknown"] = unknown
    result = check(plan(item))
    # A malformed root unknown marker is invalid; Terraform emits an object here.
    assert result.status == ("blocked" if unknown is True else status)


def test_nested_unknown_and_multiple_security_blocks():
    kind = "aws_s3_bucket_server_side_encryption_configuration"
    values = safe_values(RULES[kind])
    item = resource(kind, values)
    item["change"]["after_unknown"] = {"rule": [{"apply_server_side_encryption_by_default": True}]}
    assert check(plan(item)).status == "review_required"
    item["change"]["after_unknown"] = {}
    values["rule"].append(deepcopy(values["rule"][0]))
    assert check(plan(item)).status == "blocked"


def test_ttl_and_enabled_intake_are_not_approved():
    values = safe_values(RULES["aws_dynamodb_table"])
    values["ttl"] = [{"enabled": True, "attribute_name": "expires"}]
    assert check(plan(resource("aws_dynamodb_table", values))).status == "blocked"
    assert (
        check(plan(resource("aws_cloudwatch_event_rule", {"state": "ENABLED"}))).status == "blocked"
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("message_retention_seconds", 604800),
        ("message_retention_seconds", True),
        ("kms_master_key_id", ""),
        ("kms_master_key_id", 123),
    ],
)
def test_retention_and_key_types(field, value):
    values = safe_values(RULES["aws_sqs_queue"])
    values[field] = value
    assert check(plan(resource("aws_sqs_queue", values))).status == "blocked"


def test_only_caller_identity_data_source_is_allowed():
    item = resource("aws_caller_identity", {}, ["read"])
    item["mode"] = "data"
    assert check(plan(item)).status == "passed"
    item["type"] = "external"
    assert check(plan(item)).status == "blocked"
    item["mode"] = "managed"
    assert check(plan(item)).status == "blocked"


@pytest.mark.parametrize(
    "kind,expected_code", [("aws_s3_bucket", 0), ("aws_iam_role", 3), ("unknown", 2)]
)
def test_cli_uses_fixed_codes_and_never_echoes_plan_values(tmp_path, kind, expected_code):
    path = tmp_path / "plan.json"
    source = plan(resource(kind))
    source["variables"] = {"secret": {"value": "synthetic-sensitive-marker"}}
    path.write_text(json.dumps(source), encoding="utf-8")
    result = CliRunner().invoke(app, ["infrastructure-check", "--plan", str(path)])
    assert result.exit_code == expected_code
    assert "synthetic-sensitive-marker" not in result.output
    assert json.loads(result.output)["deployment_authorized"] is False


def test_cli_missing_directory_oversize_and_unsafe_paths(tmp_path):
    for path in (tmp_path / "missing", tmp_path, Path("//remote/share/plan.json")):
        result = CliRunner().invoke(app, ["infrastructure-check", "--plan", str(path)])
        assert result.exit_code == 2
        assert json.loads(result.output)["reasons"] == ["plan_unavailable"]
    path = tmp_path / "oversize.json"
    path.write_bytes(b" " * (MAX_BYTES + 1))
    result = CliRunner().invoke(app, ["infrastructure-check", "--plan", str(path)])
    assert result.exit_code == 2
    assert json.loads(result.output)["reasons"] == ["invalid_plan"]


def test_state_import_external_action_and_nonapplyable_changes_are_denied():
    item = resource()
    item["change"]["importing"] = {"id": "existing"}
    assert check(plan(item)).status == "blocked"
    source = plan(resource())
    source["action_invocations"] = [{"type": "aws_lambda_invoke"}]
    assert check(source).status == "blocked"
    source = plan(resource())
    source["applyable"] = False
    assert check(source).status == "blocked"


@pytest.mark.parametrize("key", ["alias/aws/sqs", "alias/customer-key", "not-an-arn", " "])
def test_managed_keys_require_a_concrete_customer_key_arn(key):
    values = safe_values(RULES["aws_sqs_queue"])
    values["kms_master_key_id"] = key
    assert check(plan(resource("aws_sqs_queue", values))).status == "blocked"
