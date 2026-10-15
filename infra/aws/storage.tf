resource "aws_kms_key" "storage" {
  description             = "${var.name} restricted application storage"
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
        Sid       = "EncryptedRuntimeLogs", Effect = "Allow"
        Principal = { Service = "logs.${var.region}.amazonaws.com" }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = { ArnEquals = { "kms:EncryptionContext:aws:logs:arn" = local.log_arn } }
      }
    ]
  })
  lifecycle { prevent_destroy = true }
  depends_on = [data.aws_caller_identity.deployment]
}

resource "aws_kms_alias" "storage" {
  name          = "alias/${var.name}-storage"
  target_key_id = aws_kms_key.storage.key_id
}

resource "aws_s3_bucket" "private" {
  for_each      = local.bucket_uses
  bucket        = "${local.prefix}-${each.key}"
  force_destroy = false
  lifecycle { prevent_destroy = true }
  depends_on = [data.aws_caller_identity.deployment]
}

resource "aws_s3_bucket_public_access_block" "private" {
  for_each                = local.bucket_uses
  bucket                  = aws_s3_bucket.private[each.key].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "private" {
  for_each = local.bucket_uses
  bucket   = aws_s3_bucket.private[each.key].id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_versioning" "private" {
  for_each = local.bucket_uses
  bucket   = aws_s3_bucket.private[each.key].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "private" {
  for_each = local.bucket_uses
  bucket   = aws_s3_bucket.private[each.key].id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.storage.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "private" {
  for_each = local.bucket_uses
  bucket   = aws_s3_bucket.private[each.key].id
  # No automatic deletion of current or noncurrent authoritative object versions.
  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    filter { prefix = "" }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

resource "aws_s3_bucket_policy" "private" {
  for_each = local.bucket_uses
  bucket   = aws_s3_bucket.private[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport", Effect = "Deny", Principal = "*", Action = "s3:*"
        Resource  = [local.bucket_arns[each.key], "${local.bucket_arns[each.key]}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyWrongEncryption", Effect = "Deny", Principal = "*", Action = "s3:PutObject"
        Resource  = "${local.bucket_arns[each.key]}/*"
        Condition = { StringNotEquals = { "s3:x-amz-server-side-encryption" = "aws:kms" } }
      },
      {
        Sid       = "DenyWrongKey", Effect = "Deny", Principal = "*", Action = "s3:PutObject"
        Resource  = "${local.bucket_arns[each.key]}/*"
        Condition = { StringNotEquals = { "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.storage.arn } }
      }
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.private]
}

resource "aws_dynamodb_table" "records" {
  name                        = "${var.name}-records"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "pk"
  range_key                   = "sk"
  deletion_protection_enabled = true
  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.storage.arn
  }
  point_in_time_recovery {
    enabled                 = true
    recovery_period_in_days = 35
  }
  lifecycle { prevent_destroy = true }
}

resource "aws_cloudwatch_log_group" "runtime" {
  name              = "/incident-investigator/${var.name}"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.storage.arn
  lifecycle { prevent_destroy = true }
}
