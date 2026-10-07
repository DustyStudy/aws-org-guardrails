# Live proof, run 2: the AI/ML SCPs, the SCP statements added since run 1
# (Amazon SES for IAM users, external AWS RAM shares) and the identity-center
# module. See probe.py and docs/PROOF.md.
#
# Run 1 (../main.tf) attached the baseline to an OU before the organization
# had any guardrails. This stack assumes the baseline is already attached
# above the sandbox OU, as it is after an organization-wide rollout. Two
# things follow from that:
#
# * Nobody in the sandbox account may create security-breakglass, so it is
#   deployed from the management account with a service-managed StackSet,
#   whose execution role (stacksets-exec-*) is exempt.
# * AWS allows five SCPs per target and FullAWSAccess takes one, so the nine
#   proof policies are split between the OU and the account.

terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0, < 7.0"
    }
  }
}

variable "management_profile" {
  description = "AWS CLI profile for the organization management account."
  type        = string
}

variable "sandbox_profile" {
  description = "AWS CLI profile for an administrator in the sandbox account."
  type        = string
}

variable "sandbox_ou_id" {
  description = "OU that holds only the sandbox account, with no SCP attached other than FullAWSAccess."
  type        = string
}

variable "identity_center_region" {
  description = "Home region of the IAM Identity Center instance."
  type        = string
}

variable "sso_user_name" {
  description = "Identity Center user who is assigned the proof permission set in the sandbox account."
  type        = string
}

provider "aws" {
  profile = var.management_profile
  region  = "us-east-1"
}

provider "aws" {
  alias   = "sandbox"
  profile = var.sandbox_profile
  region  = "us-east-1"
}

provider "aws" {
  alias   = "identity_center"
  profile = var.management_profile
  region  = var.identity_center_region
}

data "aws_partition" "current" {}

data "aws_caller_identity" "sandbox" {
  provider = aws.sandbox
}

data "aws_ssoadmin_instances" "this" {
  provider = aws.identity_center
}

data "aws_identitystore_user" "assignee" {
  provider = aws.identity_center

  identity_store_id = data.aws_ssoadmin_instances.this.identity_store_ids[0]

  alternate_identifier {
    unique_attribute {
      attribute_path  = "UserName"
      attribute_value = var.sso_user_name
    }
  }
}

locals {
  partition  = data.aws_partition.current.partition
  account_id = data.aws_caller_identity.sandbox.account_id

  # Same settings as the organization-wide rollout.
  exempt_principal_arns = [
    "arn:${local.partition}:iam::*:role/security-breakglass",
    "arn:${local.partition}:iam::*:role/security-pipeline",
    "arn:${local.partition}:iam::*:role/ProwlerScan",
    "arn:${local.partition}:iam::*:role/stacksets-exec-*",
  ]
  protected_role_name_prefixes = ["OrganizationAccountAccessRole", "security-", "ProwlerScan", "stacksets-exec-"]

  permission_set_name = "guardrails-proof"
}

# --- Exempt principal, deployed from the management account ----------------

resource "aws_cloudformation_stack_set" "breakglass" {
  name             = "guardrails-proof-breakglass"
  description      = "Proof-only exempt role for the aws-org-guardrails live proof"
  permission_model = "SERVICE_MANAGED"
  capabilities     = ["CAPABILITY_NAMED_IAM"]

  template_body = jsonencode({
    AWSTemplateFormatVersion = "2010-09-09"
    Resources = {
      Breakglass = {
        Type = "AWS::IAM::Role"
        Properties = {
          RoleName           = "security-breakglass"
          MaxSessionDuration = 3600
          AssumeRolePolicyDocument = {
            Version = "2012-10-17"
            Statement = [{
              Effect    = "Allow"
              Action    = "sts:AssumeRole"
              Principal = { AWS = { "Fn::Sub" = "arn:$${AWS::Partition}:iam::$${AWS::AccountId}:root" } }
            }]
          }
          # Proof-only: it exists to show which guardrails exempt it and
          # which do not, and to create the IAM user the probes need.
          ManagedPolicyArns = [{ "Fn::Sub" = "arn:$${AWS::Partition}:iam::aws:policy/AdministratorAccess" }]
        }
      }
    }
  })

  auto_deployment {
    enabled = false
  }

  lifecycle {
    ignore_changes = [administration_role_arn]
  }
}

# IAM is global, so a single region is enough.
resource "aws_cloudformation_stack_set_instance" "breakglass" {
  stack_set_name            = aws_cloudformation_stack_set.breakglass.name
  stack_set_instance_region = "us-east-1"

  deployment_targets {
    organizational_unit_ids = [var.sandbox_ou_id]
  }
}

# --- SCPs: OU holds four, the account holds three --------------------------

# The two baseline bundles that changed since the organization-wide rollout.
module "scp_baseline" {
  source = "../../modules/scp-baseline"

  target_ids                   = [var.sandbox_ou_id]
  name_prefix                  = "guardrails-proof"
  enabled_bundles              = ["core", "data-and-compute"]
  other_scps_per_target        = 3
  exempt_principal_arns        = local.exempt_principal_arns
  protected_role_name_prefixes = local.protected_role_name_prefixes
  deny_ses_to_iam_users        = true
}

module "ai_ml_ou" {
  source = "../../modules/ai-ml-guardrails"

  target_ids  = [var.sandbox_ou_id]
  name_prefix = "ai-ml-proof"

  enable_deny_disable_bedrock_logging_and_guardrails = true
  enable_restrict_bedrock_foundation_models          = true

  # One model with no inference profile and one that is reached through
  # one. Anthropic models need a use-case form before the first call, which
  # would stop the allowed probes for a reason unrelated to the SCP.
  allowed_bedrock_model_patterns      = ["amazon.titan*", "amazon.nova-2-lite*"]
  enable_lockdown_sagemaker_notebooks = false
  enable_require_sagemaker_encryption = false
}

module "ai_ml_account" {
  source = "../../modules/ai-ml-guardrails"

  target_ids  = [local.account_id]
  name_prefix = "ai-ml-proof"

  enable_deny_disable_bedrock_logging_and_guardrails = false
  enable_deny_bedrock_long_term_credentials          = true
  enable_lockdown_sagemaker_notebooks                = true
  enable_require_sagemaker_encryption                = true
}

# --- Identity Center: one bounded permission set ---------------------------

module "boundary" {
  source = "../../modules/permission-boundary"

  providers = {
    aws = aws.sandbox
  }
}

module "identity_center" {
  source = "../../modules/identity-center"

  providers = {
    aws = aws.identity_center
  }

  instance_arn = data.aws_ssoadmin_instances.this.arns[0]

  permission_sets = {
    (local.permission_set_name) = {
      description         = "Proof-only: administrator capped by the workload permissions boundary."
      managed_policy_arns = ["arn:${local.partition}:iam::aws:policy/AdministratorAccess"]
      # A read-only action, so a probe of it changes nothing if the deny
      # were missing.
      inline_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [{
          Sid      = "ProofInlineDeny"
          Effect   = "Deny"
          Action   = "iam:GetAccountSummary"
          Resource = "*"
        }]
      })
      permissions_boundary = {
        customer_managed_policy = {
          name = module.boundary.policy_name
          path = module.boundary.policy_path
        }
      }
    }
  }

  account_assignments = [{
    permission_set = local.permission_set_name
    principal_type = "USER"
    principal_id   = data.aws_identitystore_user.assignee.user_id
    account_id     = local.account_id
  }]
}

output "sandbox_account_id" {
  value = local.account_id
}

output "breakglass_role_arn" {
  value = "arn:${local.partition}:iam::${local.account_id}:role/security-breakglass"

  depends_on = [aws_cloudformation_stack_set_instance.breakglass]
}

output "boundary_policy_arn" {
  value = module.boundary.policy_arn
}

output "identity_center_region" {
  value = var.identity_center_region
}

output "instance_arn" {
  value = data.aws_ssoadmin_instances.this.arns[0]
}

output "permission_set_name" {
  value = local.permission_set_name
}

output "permission_set_arn" {
  value = module.identity_center.permission_set_arns[local.permission_set_name]
}

output "scp_ids" {
  value = merge(module.scp_baseline.policy_ids, module.ai_ml_ou.policy_ids, module.ai_ml_account.policy_ids)
}
