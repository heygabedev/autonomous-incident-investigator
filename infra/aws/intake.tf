variable "alarm_arns" {
  type    = set(string)
  default = []
  validation {
    condition     = length(var.alarm_arns) <= 100 && alltrue([for arn in var.alarm_arns : can(regex("^arn:aws:cloudwatch:${var.region}:${var.account_id}:alarm:[^*?]+$", arn))])
    error_message = "Select at most 100 exact alarm ARNs in the configured account and Region."
  }
}

variable "enable_ingestion" {
  type    = bool
  default = false
  validation {
    condition     = !var.enable_ingestion || length(var.alarm_arns) > 0
    error_message = "Alarm ingestion requires an explicit alarm allowlist."
  }
}

locals {
  rule_arn    = "arn:aws:events:${var.region}:${var.account_id}:rule/${var.name}-alarms"
  queue_names = toset(["intake", "processing-dlq", "delivery-dlq"])
  queue_arns  = { for name in local.queue_names : name => "arn:aws:sqs:${var.region}:${var.account_id}:${var.name}-${name}" }
}

resource "aws_kms_key" "queue" {
  description             = "${var.name} alarm queues, including retained dead letters"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountIAMDelegation", Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
        Action    = "kms:*", Resource = "*"
      },
      {
        Sid       = "EventBridgeEncryption", Effect = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = ["kms:GenerateDataKey", "kms:Decrypt"], Resource = "*"
        Condition = { StringEquals = { "aws:SourceAccount" = var.account_id } }
      }
    ]
  })
  lifecycle { prevent_destroy = true }
  depends_on = [data.aws_caller_identity.deployment]
}

resource "aws_kms_alias" "queue" {
  name          = "alias/${var.name}-queues"
  target_key_id = aws_kms_key.queue.key_id
}

resource "aws_sqs_queue" "protected" {
  for_each                          = local.queue_names
  name                              = "${var.name}-${each.key}"
  message_retention_seconds         = 1209600
  visibility_timeout_seconds        = 300
  receive_wait_time_seconds         = 20
  max_message_size                  = 65536
  kms_master_key_id                 = aws_kms_key.queue.arn
  kms_data_key_reuse_period_seconds = 300
  lifecycle { prevent_destroy = true }
}

resource "aws_sqs_queue_redrive_policy" "intake" {
  queue_url = aws_sqs_queue.protected["intake"].id
  redrive_policy = jsonencode({
    deadLetterTargetArn = local.queue_arns["processing-dlq"]
    maxReceiveCount     = 5
  })
}

resource "aws_sqs_queue_redrive_allow_policy" "processing" {
  queue_url = aws_sqs_queue.protected["processing-dlq"].id
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [local.queue_arns["intake"]]
  })
}

resource "aws_sqs_queue_redrive_allow_policy" "delivery" {
  queue_url            = aws_sqs_queue.protected["delivery-dlq"].id
  redrive_allow_policy = jsonencode({ redrivePermission = "denyAll" })
}

resource "aws_cloudwatch_event_rule" "alarms" {
  name  = "${var.name}-alarms"
  state = var.enable_ingestion ? "ENABLED" : "DISABLED"
  event_pattern = jsonencode({
    source        = ["aws.cloudwatch"]
    "detail-type" = ["CloudWatch Alarm State Change"]
    account       = [var.account_id]
    region        = [var.region]
    # An empty allowlist must not turn into a wildcard event pattern.
    resources = length(var.alarm_arns) > 0 ? sort(tolist(var.alarm_arns)) : ["arn:aws:cloudwatch:${var.region}:${var.account_id}:alarm:disabled-no-alarms-selected"]
    detail    = { state = { value = ["ALARM"] } }
  })
}

resource "aws_sqs_queue_policy" "restricted" {
  for_each  = local.queue_names
  queue_url = aws_sqs_queue.protected[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid      = "DenyInsecureTransport", Effect = "Deny", Principal = "*", Action = "sqs:*"
        Resource = local.queue_arns[each.key], Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid      = "DenyUnapprovedConsumers", Effect = "Deny", Principal = "*"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility"]
        Resource = local.queue_arns[each.key]
        Condition = { ArnNotEquals = {
          "aws:PrincipalArn" = each.key == "intake" ? [var.deployment_role_arn, local.runtime_role_arn] : [var.deployment_role_arn]
        } }
      },
      {
        Sid       = "DenyRuntimeQueueAdministration", Effect = "Deny", Principal = "*"
        Action    = ["sqs:PurgeQueue", "sqs:DeleteQueue", "sqs:SetQueueAttributes", "sqs:AddPermission", "sqs:RemovePermission"]
        Resource  = local.queue_arns[each.key]
        Condition = { ArnNotEquals = { "aws:PrincipalArn" = var.deployment_role_arn } }
      }
      ], each.key == "processing-dlq" ? [] : [{
        Sid    = "OnlySelectedEventRule", Effect = "Allow", Principal = { Service = "events.amazonaws.com" }
        Action = "sqs:SendMessage", Resource = local.queue_arns[each.key]
        Condition = {
          ArnEquals    = { "aws:SourceArn" = local.rule_arn }
          StringEquals = { "aws:SourceAccount" = var.account_id }
        }
      }]
    )
  })
}

resource "aws_cloudwatch_event_target" "intake" {
  rule      = aws_cloudwatch_event_rule.alarms.name
  target_id = "investigation-intake"
  arn       = local.queue_arns["intake"]
  dead_letter_config { arn = local.queue_arns["delivery-dlq"] }
  retry_policy {
    maximum_event_age_in_seconds = 86400
    maximum_retry_attempts       = 10
  }
  input_transformer {
    input_paths    = { event_id = "$.id", occurred_at = "$.time", alarm_arn = "$.resources[0]" }
    input_template = <<-JSON
      {"schema_version":"1.0.0","event_id":<event_id>,"occurred_at":<occurred_at>,"alarm_arn":<alarm_arn>,"account_id":"${var.account_id}","region":"${var.region}","state":"ALARM"}
    JSON
  }
  depends_on = [aws_sqs_queue_policy.restricted, aws_sqs_queue_redrive_policy.intake]
}

resource "aws_cloudwatch_metric_alarm" "dead_letters" {
  for_each            = toset(["processing-dlq", "delivery-dlq"])
  alarm_name          = "${var.name}-${each.key}-nonempty"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  dimensions          = { QueueName = aws_sqs_queue.protected[each.key].name }
  # No notification destination is created or subscribed without an operator choice.
  alarm_actions = []
}

resource "aws_cloudwatch_metric_alarm" "backlog" {
  alarm_name          = "${var.name}-intake-age"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ApproximateAgeOfOldestMessage"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Maximum"
  threshold           = 300
  treat_missing_data  = "notBreaching"
  dimensions          = { QueueName = aws_sqs_queue.protected["intake"].name }
  alarm_actions       = []
}
