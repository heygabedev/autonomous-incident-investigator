terraform {
  required_version = "= 1.16.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.69.0"
    }
  }
}

provider "aws" {
  region              = var.region
  profile             = var.deployment_profile
  allowed_account_ids = [var.account_id]
  assume_role {
    role_arn     = var.deployment_role_arn
    session_name = "incident-infrastructure"
  }
  default_tags {
    tags = {
      Project   = var.name
      ManagedBy = "Terraform"
      DataClass = "restricted"
    }
  }
}

data "aws_caller_identity" "deployment" {
  lifecycle {
    postcondition {
      condition     = self.account_id == var.account_id
      error_message = "The deployment identity belongs to a different account."
    }
  }
}
