# GovCloud (US) rollout. The modules read the partition from the provider,
# so the only differences from the commercial example are the region, the
# aws-us-gov ARNs for exempt principals and the us-gov-* allowed regions.
# The policies module rejects a mix of partitions at plan time.

terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0, < 7.0"
    }
  }
}

provider "aws" {
  region = "us-gov-west-1"
}

provider "aws" {
  alias  = "workload"
  region = "us-gov-west-1"

  assume_role {
    role_arn = "arn:aws-us-gov:iam::${var.workload_account_id}:role/OrganizationAccountAccessRole"
  }
}

variable "workload_ou_ids" {
  description = "GovCloud OUs that receive the SCP bundles."
  type        = list(string)
}

variable "workload_account_id" {
  description = "GovCloud member account that receives the permissions boundary."
  type        = string
}

module "scp_baseline" {
  source = "../../modules/scp-baseline"

  target_ids = var.workload_ou_ids
  exempt_principal_arns = [
    "arn:aws-us-gov:iam::*:role/security-breakglass",
    "arn:aws-us-gov:iam::*:role/security-pipeline",
  ]
  allowed_regions = ["us-gov-west-1", "us-gov-east-1"]
}

module "boundary" {
  source = "../../modules/permission-boundary"

  providers = {
    aws = aws.workload
  }
}

output "scp_ids" {
  value = module.scp_baseline.policy_ids
}

output "boundary_arn" {
  value = module.boundary.policy_arn
}
