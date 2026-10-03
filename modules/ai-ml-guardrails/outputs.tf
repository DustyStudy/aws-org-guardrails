output "policy_ids" {
  description = "Map of enabled policy name to its Organizations policy ID."
  value       = { for name, p in aws_organizations_policy.this : name => p.id }
}

output "enabled_policies" {
  description = "Names of the policies that were created (i.e. enabled via their enable_* variable)."
  value       = keys(local.enabled_policies)
}
