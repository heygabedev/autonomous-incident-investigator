mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "111122223333"
      arn        = "arn:aws:sts::111122223333:assumed-role/Infrastructure/test"
    }
  }
  mock_resource "aws_kms_key" {
    defaults = {
      arn    = "arn:aws:kms:eu-central-1:111122223333:key/00000000-0000-0000-0000-000000000001"
      key_id = "00000000-0000-0000-0000-000000000001"
    }
  }
  mock_resource "aws_iam_policy" {
    defaults = { arn = "arn:aws:iam::111122223333:policy/mock-boundary" }
  }
}

variables {
  name                = "incident-test"
  account_id          = "111122223333"
  region              = "eu-central-1"
  deployment_profile  = "synthetic-test"
  deployment_role_arn = "arn:aws:iam::111122223333:role/Infrastructure"
  operator_role_arn   = "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/eu-central-1/AWSReservedSSO_Operator_0123456789abcdef"
}

run "protected_storage" {
  command = apply
  assert {
    condition     = length(aws_s3_bucket.private) == 5 && alltrue([for b in aws_s3_bucket.private : !b.force_destroy])
    error_message = "All five restricted stores must reject forced deletion."
  }
  assert {
    condition     = alltrue([for b in aws_s3_bucket_versioning.private : b.versioning_configuration[0].status == "Enabled"])
    error_message = "Every store must retain object versions."
  }
  assert {
    condition     = alltrue([for b in aws_s3_bucket_public_access_block.private : b.block_public_acls && b.block_public_policy && b.ignore_public_acls && b.restrict_public_buckets])
    error_message = "Every public-access control must be enabled."
  }
  assert {
    condition     = aws_dynamodb_table.records.deletion_protection_enabled && aws_dynamodb_table.records.point_in_time_recovery[0].enabled && aws_dynamodb_table.records.point_in_time_recovery[0].recovery_period_in_days == 35
    error_message = "Canonical records need deletion protection and 35-day PITR."
  }
  assert {
    condition     = aws_kms_key.storage.enable_key_rotation && aws_kms_key.storage.deletion_window_in_days == 30
    error_message = "Storage key rotation and the recovery window must remain enabled."
  }
  assert {
    condition     = !output.activation.live_runtime_enabled && !output.activation.private_evaluation
    error_message = "Provisioning does not enable live runtime or private evaluation."
  }
}

run "wrong_deployment_account" {
  command = plan
  override_data {
    target = data.aws_caller_identity.deployment
    values = { account_id = "999999999999" }
  }
  expect_failures = [data.aws_caller_identity.deployment]
}

run "foreign_deployment_role" {
  command = plan
  variables { deployment_role_arn = "arn:aws:iam::999999999999:role/Infrastructure" }
  expect_failures = [var.deployment_role_arn]
}

run "safe_intake_defaults" {
  command = apply
  assert {
    condition     = aws_cloudwatch_event_rule.alarms.state == "DISABLED" && !output.integration.assumption_enabled
    error_message = "Intake and role assumption must be opt-in."
  }
  assert {
    condition     = alltrue([for queue in aws_sqs_queue.protected : queue.message_retention_seconds == 1209600 && queue.kms_master_key_id == aws_kms_key.queue.arn && queue.max_message_size == 65536])
    error_message = "Queues need 14-day retention, encryption and bounded messages."
  }
  assert {
    condition     = jsondecode(aws_sqs_queue_redrive_policy.intake.redrive_policy).maxReceiveCount == 5 && jsondecode(aws_sqs_queue_redrive_allow_policy.processing.redrive_allow_policy).sourceQueueArns == [local.queue_arns["intake"]]
    error_message = "Processing DLQ must accept only bounded retries from the owned intake."
  }
  assert {
    condition     = jsondecode(aws_sqs_queue_redrive_allow_policy.delivery.redrive_allow_policy).redrivePermission == "denyAll"
    error_message = "Event delivery DLQ must not become another queue's processing DLQ."
  }
  assert {
    condition     = jsondecode(aws_iam_role.collector.assume_role_policy).Statement[0].Effect == "Deny" && jsondecode(aws_iam_role.runtime.assume_role_policy).Statement[0].Effect == "Deny"
    error_message = "Default trust must not enable either role."
  }
  assert {
    condition     = alltrue([for statement in jsondecode(aws_iam_policy.collector.policy).Statement : statement.Effect == "Deny"])
    error_message = "An empty collector allowlist grants no reads."
  }
}

run "scoped_collector_configuration" {
  command = plan
  variables {
    lambda_function_arns           = ["arn:aws:lambda:eu-central-1:111122223333:function:checkout"]
    ecs_service_arns               = ["arn:aws:ecs:eu-central-1:111122223333:service/production/checkout"]
    dynamodb_table_arns            = ["arn:aws:dynamodb:eu-central-1:111122223333:table/orders"]
    log_group_arns                 = ["arn:aws:logs:eu-central-1:111122223333:log-group:/aws/lambda/checkout"]
    allow_wildcard_telemetry_reads = true
  }
  assert {
    condition = toset(flatten([for statement in jsondecode(aws_iam_policy.collector.policy).Statement : statement.Action if statement.Effect == "Allow"])) == toset([
      "lambda:GetFunctionConfiguration", "ecs:DescribeServices", "dynamodb:DescribeTable",
      "logs:StartQuery", "logs:GetQueryResults", "logs:StopQuery", "cloudwatch:GetMetricData", "elasticloadbalancing:DescribeTargetHealth"
    ])
    error_message = "Collector grants must match the reviewed read-only contracts exactly."
  }
  assert {
    condition     = alltrue([for statement in jsondecode(aws_iam_policy.collector.policy).Statement : statement.Condition.StringEquals["aws:RequestedRegion"] == var.region if statement.Effect == "Allow"])
    error_message = "Every collector grant must be restricted to the selected Region."
  }
}

run "no_wildcard_telemetry_without_review" {
  command = plan
  variables { log_group_arns = ["arn:aws:logs:eu-central-1:111122223333:log-group:/aws/lambda/checkout"] }
  assert {
    condition     = alltrue([for statement in jsondecode(aws_iam_policy.collector.policy).Statement : statement.Effect == "Deny"])
    error_message = "Starting log queries requires approval for the wildcard cleanup limitation."
  }
}

run "runtime_permissions_are_separate" {
  command = apply
  assert {
    condition     = !strcontains(aws_iam_policy.runtime.policy, "${local.bucket_arns["quarantine"]}") && !strcontains(aws_iam_policy.runtime.policy, "${local.bucket_arns["datasets"]}")
    error_message = "Runtime must not read quarantine or evaluation datasets."
  }
  assert {
    condition     = !strcontains(aws_iam_policy.runtime.policy, "sqs:PurgeQueue") && !strcontains(aws_iam_policy.runtime.policy, "dynamodb:DeleteItem") && !strcontains(aws_iam_policy.runtime.policy, "s3:DeleteObject")
    error_message = "Runtime must not erase retained records or queues."
  }
  assert {
    condition     = alltrue([for role in [aws_iam_role.runtime, aws_iam_role.collector] : role.permissions_boundary != null && role.max_session_duration == 3600])
    error_message = "Both roles need bounded permissions and temporary sessions."
  }
  assert {
    condition     = alltrue([for policy in aws_s3_bucket_policy.private : length(jsondecode(policy.policy).Statement) == 3 && jsondecode(policy.policy).Statement[2].Condition.StringNotEquals["s3:x-amz-server-side-encryption-aws-kms-key-id"] == aws_kms_key.storage.arn])
    error_message = "Every object upload must use the selected KMS key."
  }
}

run "explicit_alarm_selection" {
  command = plan
  variables {
    alarm_arns       = ["arn:aws:cloudwatch:eu-central-1:111122223333:alarm:checkout-errors"]
    enable_ingestion = true
  }
  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.alarms.event_pattern).resources == ["arn:aws:cloudwatch:eu-central-1:111122223333:alarm:checkout-errors"]
    error_message = "Only explicitly selected alarms may route to intake."
  }
  assert {
    condition     = !strcontains(aws_cloudwatch_event_target.intake.input_transformer[0].input_template, "reason") && length(aws_cloudwatch_event_target.intake.input_transformer[0].input_paths) == 3
    error_message = "Ordinary intake excludes free-form alarm reasons and configuration."
  }
}

run "deny_empty_alarm_activation" {
  command = plan
  variables { enable_ingestion = true }
  expect_failures = [var.enable_ingestion]
}

run "deny_foreign_function" {
  command = plan
  variables { lambda_function_arns = ["arn:aws:lambda:eu-central-1:999999999999:function:checkout"] }
  expect_failures = [var.lambda_function_arns]
}

run "deny_wildcard_log_group" {
  command = plan
  variables { log_group_arns = ["arn:aws:logs:eu-central-1:111122223333:log-group:*"] }
  expect_failures = [var.log_group_arns]
}

run "deny_foreign_region_table" {
  command = plan
  variables { dynamodb_table_arns = ["arn:aws:dynamodb:us-east-1:111122223333:table/orders"] }
  expect_failures = [var.dynamodb_table_arns]
}

run "deny_wildcard_operator" {
  command = plan
  variables { operator_role_arn = "arn:aws:iam::111122223333:root" }
  expect_failures = [var.operator_role_arn]
}

run "deny_short_ecs_arn" {
  command = plan
  variables { ecs_service_arns = ["arn:aws:ecs:eu-central-1:111122223333:service/checkout"] }
  expect_failures = [var.ecs_service_arns]
}

run "deny_foreign_alarm" {
  command = plan
  variables { alarm_arns = ["arn:aws:cloudwatch:us-east-1:111122223333:alarm:checkout"] }
  expect_failures = [var.alarm_arns]
}
