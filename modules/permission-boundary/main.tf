data "aws_partition" "current" {}

module "policies" {
  source = "../policies"

  partition            = data.aws_partition.current.partition
  boundary_policy_name = var.policy_name
  boundary_policy_path = var.policy_path
  delegated_role_path  = var.delegated_role_path

  service_linked_role_services = var.service_linked_role_services
}

resource "aws_iam_policy" "boundary" {
  name        = var.policy_name
  path        = var.policy_path
  description = "Permissions boundary for workload principals: blocks privilege escalation, boundary removal and changes outside ${var.delegated_role_path}."
  policy      = module.policies.permissions_boundary_policy
  tags        = var.tags
}
