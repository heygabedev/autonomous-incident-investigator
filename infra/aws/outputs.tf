output "storage" {
  value = {
    bucket_arns = local.bucket_arns
    kms_key_arn = aws_kms_key.storage.arn
    table_arn   = local.table_arn
  }
}

output "activation" {
  value = {
    live_runtime_enabled   = false
    private_evaluation     = false
    deployment_performed   = "Terraform output is not evidence of runtime activation or recovery readiness."
    required_configuration = "An approved deployment profile/role and independently verified MFA configuration are prerequisites."
  }
}

output "integration" {
  value = {
    queue_urls         = { for use, queue in aws_sqs_queue.protected : use => queue.id }
    rule_name          = aws_cloudwatch_event_rule.alarms.name
    ingestion_enabled  = var.enable_ingestion
    assumption_enabled = var.enable_role_assumption
    collector_role_arn = local.collector_role_arn
    runtime_role_arn   = local.runtime_role_arn
  }
}
