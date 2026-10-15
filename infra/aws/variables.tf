variable "name" {
  type        = string
  description = "Stable resource namespace. Changing this requires a reviewed parallel deployment."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,19}$", var.name))
    error_message = "Use 3-20 lowercase letters, digits or hyphens, starting with a letter."
  }
}

variable "account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "An explicit 12-digit AWS account is required."
  }
}

variable "region" {
  type = string
  validation {
    condition     = can(regex("^(us|eu|ap|ca|sa|me|af|il|mx)-(central|north|south|east|west|northeast|southeast|northwest|southwest)-[0-9]$", var.region))
    error_message = "Use an explicit commercial-partition AWS Region."
  }
}

variable "deployment_profile" {
  type        = string
  description = "Explicit local Identity Center deployment profile; no application credentials."
  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$", var.deployment_profile))
    error_message = "An explicit named deployment profile is required."
  }
}

variable "deployment_role_arn" {
  type = string
  validation {
    condition     = can(regex("^arn:aws:iam::${var.account_id}:role/[A-Za-z0-9_+=,.@/-]+$", var.deployment_role_arn))
    error_message = "The dedicated deployment role must be in the selected account."
  }
}

locals {
  prefix      = "${var.name}-${var.account_id}-${var.region}"
  bucket_uses = toset(["quarantine", "datasets", "runs", "audit", "artifacts"])
  bucket_arns = { for use in local.bucket_uses : use => "arn:aws:s3:::${local.prefix}-${use}" }
  table_arn   = "arn:aws:dynamodb:${var.region}:${var.account_id}:table/${var.name}-records"
  log_arn     = "arn:aws:logs:${var.region}:${var.account_id}:log-group:/incident-investigator/${var.name}"
}
