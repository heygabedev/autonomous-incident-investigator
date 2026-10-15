variable "operator_role_arn" {
  type        = string
  description = "Exact existing Identity Center role ARN; no permission-set or MFA changes are made."
  validation {
    condition     = can(regex("^arn:aws:iam::${var.account_id}:role/aws-reserved/sso.amazonaws.com/([a-z0-9-]+/)?AWSReservedSSO_[A-Za-z0-9_]+_[a-f0-9]{16}$", var.operator_role_arn))
    error_message = "Use an exact Identity Center role ARN in the selected account."
  }
}

variable "enable_role_assumption" {
  type        = bool
  default     = false
  description = "Leave false until independent MFA, IAM negative tests and runtime dispatch gates are approved."
}

variable "allow_wildcard_telemetry_reads" {
  type        = bool
  default     = false
  description = "Explicit review of account-wide classic metrics, ELB health and Logs query cleanup access."
}

variable "log_group_arns" {
  type    = set(string)
  default = []
  validation {
    condition     = length(var.log_group_arns) <= 100 && alltrue([for arn in var.log_group_arns : can(regex("^arn:aws:logs:${var.region}:${var.account_id}:log-group:[A-Za-z0-9_./#-]+$", arn))])
    error_message = "Select exact log-group ARNs without trailing wildcards."
  }
}

variable "lambda_function_arns" {
  type    = set(string)
  default = []
  validation {
    condition     = length(var.lambda_function_arns) <= 100 && alltrue([for arn in var.lambda_function_arns : can(regex("^arn:aws:lambda:${var.region}:${var.account_id}:function:[A-Za-z0-9_-]+$", arn))])
    error_message = "Select exact unqualified function ARNs in the configured account and Region."
  }
}

variable "ecs_service_arns" {
  type    = set(string)
  default = []
  validation {
    condition     = length(var.ecs_service_arns) <= 100 && alltrue([for arn in var.ecs_service_arns : can(regex("^arn:aws:ecs:${var.region}:${var.account_id}:service/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+$", arn))])
    error_message = "Select exact long-format ECS service ARNs."
  }
}

variable "dynamodb_table_arns" {
  type    = set(string)
  default = []
  validation {
    condition     = length(var.dynamodb_table_arns) <= 100 && alltrue([for arn in var.dynamodb_table_arns : can(regex("^arn:aws:dynamodb:${var.region}:${var.account_id}:table/[A-Za-z0-9_.-]+$", arn))])
    error_message = "Select exact workload table ARNs. Collector access is metadata-only."
  }
}

locals {
  runtime_role_arn   = "arn:aws:iam::${var.account_id}:role/${var.name}-runtime"
  collector_role_arn = "arn:aws:iam::${var.account_id}:role/${var.name}-collector"
  regional           = { StringEquals = { "aws:RequestedRegion" = var.region } }
  operator_trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = var.enable_role_assumption ? "Allow" : "Deny"
      Principal = { AWS = var.operator_role_arn }
      Action    = "sts:AssumeRole"
    }]
  })
  collector_statements = concat(
    [{ Sid = "DenyWrongRegion", Effect = "Deny", Action = "*", Resource = "*", Condition = { StringNotEquals = { "aws:RequestedRegion" = var.region } } }],
    length(var.lambda_function_arns) == 0 ? [] : [{ Sid = "SelectedFunctions", Effect = "Allow", Action = ["lambda:GetFunctionConfiguration"], Resource = sort(tolist(var.lambda_function_arns)), Condition = local.regional }],
    length(var.dynamodb_table_arns) == 0 ? [] : [{ Sid = "SelectedTableMetadata", Effect = "Allow", Action = ["dynamodb:DescribeTable"], Resource = sort(tolist(var.dynamodb_table_arns)), Condition = local.regional }],
    length(var.ecs_service_arns) == 0 ? [] : [{ Sid = "SelectedServices", Effect = "Allow", Action = ["ecs:DescribeServices"], Resource = sort(tolist(var.ecs_service_arns)), Condition = local.regional }],
    length(var.log_group_arns) == 0 || !var.allow_wildcard_telemetry_reads ? [] : [{ Sid = "SelectedStructuredLogs", Effect = "Allow", Action = ["logs:StartQuery", "logs:GetQueryResults"], Resource = [for arn in sort(tolist(var.log_group_arns)) : "${arn}:*"], Condition = local.regional }],
    !var.allow_wildcard_telemetry_reads ? [] : [{ Sid = "ReviewedWildcardTelemetry", Effect = "Allow", Action = ["cloudwatch:GetMetricData", "elasticloadbalancing:DescribeTargetHealth", "logs:StopQuery"], Resource = "*", Condition = local.regional }]
  )
}

resource "aws_iam_policy" "collector" {
  name   = "${var.name}-collector-boundary"
  policy = jsonencode({ Version = "2012-10-17", Statement = local.collector_statements })
}

resource "aws_iam_role" "collector" {
  name                 = "${var.name}-collector"
  assume_role_policy   = local.operator_trust
  permissions_boundary = aws_iam_policy.collector.arn
  max_session_duration = 3600
  lifecycle { prevent_destroy = true }
  depends_on = [data.aws_caller_identity.deployment]
}

resource "aws_iam_role_policy_attachment" "collector" {
  role       = aws_iam_role.collector.name
  policy_arn = aws_iam_policy.collector.arn
}

resource "aws_iam_policy" "runtime" {
  name = "${var.name}-runtime-boundary"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "RuntimeLogs", Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${local.log_arn}:*", Condition = local.regional
      },
      {
        Sid      = "RuntimeRecords", Effect = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = local.table_arn
        Condition = {
          StringEquals              = { "aws:RequestedRegion" = var.region }
          "ForAllValues:StringLike" = { "dynamodb:LeadingKeys" = ["runtime#*"] }
        }
      },
      {
        Sid      = "CanonicalCaseReads", Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:Query"]
        Resource = local.table_arn
        Condition = {
          StringEquals              = { "aws:RequestedRegion" = var.region }
          "ForAllValues:StringLike" = { "dynamodb:LeadingKeys" = ["case#*"] }
        }
      },
      {
        Sid      = "ReadApprovedArtifacts", Effect = "Allow", Action = ["s3:GetObject", "s3:GetObjectVersion"]
        Resource = ["${local.bucket_arns["artifacts"]}/releases/*", "${local.bucket_arns["runs"]}/reports/*"]
      },
      {
        Sid      = "WriteReportsAndAudit", Effect = "Allow", Action = ["s3:PutObject"]
        Resource = ["${local.bucket_arns["runs"]}/reports/*", "${local.bucket_arns["audit"]}/events/*"]
      },
      {
        Sid      = "StorageEncryption", Effect = "Allow", Action = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = aws_kms_key.storage.arn
        Condition = { StringEquals = {
          "kms:ViaService"                   = "s3.${var.region}.amazonaws.com"
          "kms:CallerAccount"                = var.account_id
          "kms:EncryptionContext:aws:s3:arn" = [local.bucket_arns["runs"], local.bucket_arns["audit"], local.bucket_arns["artifacts"]]
        } }
      },
      {
        Sid      = "AcknowledgeIntake", Effect = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"]
        Resource = local.queue_arns["intake"], Condition = local.regional
      },
      {
        Sid       = "DecryptIntake", Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.queue.arn
        Condition = { StringEquals = { "kms:ViaService" = "sqs.${var.region}.amazonaws.com", "kms:CallerAccount" = var.account_id } }
      }
    ]
  })
}

resource "aws_iam_role" "runtime" {
  name                 = "${var.name}-runtime"
  assume_role_policy   = local.operator_trust
  permissions_boundary = aws_iam_policy.runtime.arn
  max_session_duration = 3600
  lifecycle { prevent_destroy = true }
  depends_on = [data.aws_caller_identity.deployment]
}

resource "aws_iam_role_policy_attachment" "runtime" {
  role       = aws_iam_role.runtime.name
  policy_arn = aws_iam_policy.runtime.arn
}
