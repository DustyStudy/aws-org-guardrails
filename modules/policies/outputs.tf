output "scp_policies" {
  description = "Map of SCP bundle name to minified policy JSON. Empty when exempt_principal_arns is null."
  value       = local.scp_policies
}

output "permissions_boundary_policy" {
  description = "Permissions boundary policy JSON. Account-agnostic: it uses $${aws:PrincipalAccount}."
  value       = local.permissions_boundary_policy
}

output "boundary_policy_arn_template" {
  description = "ARN of the boundary policy with $${aws:PrincipalAccount} in place of the account ID, as the policies reference it."
  value       = local.boundary_arn
}
