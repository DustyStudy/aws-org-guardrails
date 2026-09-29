# Live proof: attach the guardrails to a sandbox OU holding one account, then
# probe them with real API calls (see probe.py and docs/PROOF.md).
#
# The account is moved into the sandbox OU with the AWS CLI, not Terraform:
# destroying an aws_organizations_account resource removes the account from
# the organization, which is not something a test should ever risk.
#
# Order matters. The test roles are created before the SCPs are attached,
# because afterwards nobody in the account may create a role under a
# protected prefix (security-*).

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
  description = "OU that holds only the sandbox account."
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

data "aws_caller_identity" "sandbox" {
  provider = aws.sandbox
}

locals {
  account_root = "arn:aws:iam::${data.aws_caller_identity.sandbox.account_id}:root"

  # Same settings as the organization-wide rollout, so the proof exercises
  # the configuration that goes live.
  exempt_principal_arns = [
    "arn:aws:iam::*:role/security-breakglass",
    "arn:aws:iam::*:role/security-pipeline",
    "arn:aws:iam::*:role/ProwlerScan",
    "arn:aws:iam::*:role/stacksets-exec-*",
  ]
  protected_role_name_prefixes = ["OrganizationAccountAccessRole", "security-", "ProwlerScan", "stacksets-exec-"]
  allowed_regions              = ["us-east-1", "us-east-2", "us-west-2"]
}

# --- Sandbox account: boundary and test principals -------------------------

module "boundary" {
  source = "../modules/permission-boundary"

  providers = {
    aws = aws.sandbox
  }
}

data "aws_iam_policy_document" "trust_account" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }
  }
}

# Exempt principal. Proof-only: in a real rollout this role is created from
# the management account (see docs/DESIGN.md).
resource "aws_iam_role" "breakglass" {
  provider = aws.sandbox

  name                 = "security-breakglass"
  assume_role_policy   = data.aws_iam_policy_document.trust_account.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "breakglass_admin" {
  #checkov:skip=CKV_AWS_274:Proof-only break-glass principal; it exists to show the SCP exemption works.
  provider = aws.sandbox

  role       = aws_iam_role.breakglass.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Delegated principal: full admin identity policy, capped by the boundary.
resource "aws_iam_role" "app_deployer" {
  provider = aws.sandbox

  name                 = "app-deployer"
  path                 = "/workload/"
  assume_role_policy   = data.aws_iam_policy_document.trust_account.json
  permissions_boundary = module.boundary.policy_arn
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "app_deployer_admin" {
  #checkov:skip=CKV_AWS_274:Proof-only principal; the permissions boundary is what is under test.
  provider = aws.sandbox

  role       = aws_iam_role.app_deployer.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# --- Management account: SCPs on the sandbox OU ----------------------------

module "scp_baseline" {
  source = "../modules/scp-baseline"

  target_ids                   = [var.sandbox_ou_id]
  name_prefix                  = "guardrails-proof"
  exempt_principal_arns        = local.exempt_principal_arns
  protected_role_name_prefixes = local.protected_role_name_prefixes
  allowed_regions              = local.allowed_regions

  depends_on = [
    aws_iam_role_policy_attachment.breakglass_admin,
    aws_iam_role_policy_attachment.app_deployer_admin,
  ]
}

output "sandbox_account_id" {
  value = data.aws_caller_identity.sandbox.account_id
}

output "breakglass_role_arn" {
  value = aws_iam_role.breakglass.arn
}

output "app_deployer_role_arn" {
  value = aws_iam_role.app_deployer.arn
}

output "boundary_policy_arn" {
  value = module.boundary.policy_arn
}

output "scp_ids" {
  value = module.scp_baseline.policy_ids
}
