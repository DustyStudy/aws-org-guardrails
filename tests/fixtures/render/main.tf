# Renders the policies module with fixed inputs so the Python policy tests
# can evaluate the exact JSON Terraform produces. No provider is involved,
# so `terraform plan` works offline and without credentials.

terraform {
  required_version = ">= 1.9"
}

variable "partition" {
  type    = string
  default = "aws"
}

variable "allowed_regions" {
  type    = list(string)
  default = ["us-east-1", "us-west-2"]
}

module "policies" {
  source = "../../../modules/policies"

  partition       = var.partition
  allowed_regions = var.allowed_regions
  exempt_principal_arns = [
    "arn:${var.partition}:iam::*:role/security-breakglass",
    "arn:${var.partition}:iam::*:role/security-pipeline",
  ]
}

output "scp_policies" {
  value = module.policies.scp_policies
}

output "permissions_boundary_policy" {
  value = module.policies.permissions_boundary_policy
}
