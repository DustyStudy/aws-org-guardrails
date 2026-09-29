# Commercial-partition rollout from the management account (or an account
# delegated for Organizations policy management and Identity Center).
#
#   1. SCP bundles attached to the workload OUs.
#   2. The permissions boundary created in a member account. Repeat the
#      module (or run this stack per account) for every account that gets a
#      bounded permission set, because Identity Center resolves a customer
#      managed boundary by name inside each assigned account.
#   3. Permission sets that carry that boundary, assigned to groups.

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
  region = "us-east-1"
}

provider "aws" {
  alias  = "workload"
  region = "us-east-1"

  assume_role {
    role_arn = "arn:aws:iam::${var.workload_account_id}:role/OrganizationAccountAccessRole"
  }
}

variable "workload_ou_ids" {
  description = "OUs that receive the SCP bundles."
  type        = list(string)
}

variable "workload_account_id" {
  description = "Member account that receives the permissions boundary and the Developer assignment."
  type        = string
}

variable "developer_group_id" {
  description = "Identity Store group ID for developers."
  type        = string
}

variable "auditor_group_id" {
  description = "Identity Store group ID for auditors."
  type        = string
}

data "aws_ssoadmin_instances" "this" {}

module "scp_baseline" {
  source = "../../modules/scp-baseline"

  target_ids = var.workload_ou_ids
  exempt_principal_arns = [
    "arn:aws:iam::*:role/security-breakglass",
    "arn:aws:iam::*:role/security-pipeline",
  ]
  allowed_regions = ["us-east-1", "us-west-2"]
}

module "boundary" {
  source = "../../modules/permission-boundary"

  providers = {
    aws = aws.workload
  }
}

module "identity_center" {
  source = "../../modules/identity-center"

  instance_arn = one(data.aws_ssoadmin_instances.this.arns)

  permission_sets = {
    Developer = {
      description         = "Build and run workloads inside the permissions boundary"
      managed_policy_arns = ["arn:aws:iam::aws:policy/PowerUserAccess"]
      permissions_boundary = {
        customer_managed_policy = {
          name = module.boundary.policy_name
          path = module.boundary.policy_path
        }
      }
    }
    SecurityAuditor = {
      description         = "Read-only security review"
      session_duration    = "PT4H"
      managed_policy_arns = ["arn:aws:iam::aws:policy/SecurityAudit", "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"]
      permissions_boundary = {
        managed_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
      }
    }
  }

  account_assignments = [
    { permission_set = "Developer", principal_id = var.developer_group_id, account_id = var.workload_account_id },
    { permission_set = "SecurityAuditor", principal_id = var.auditor_group_id, account_id = var.workload_account_id },
  ]
}

output "scp_ids" {
  value = module.scp_baseline.policy_ids
}

output "permission_set_arns" {
  value = module.identity_center.permission_set_arns
}
