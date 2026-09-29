output "policy_ids" {
  description = "Map of bundle name to SCP ID."
  value       = { for name, p in aws_organizations_policy.this : name => p.id }
}

output "policy_arns" {
  description = "Map of bundle name to SCP ARN."
  value       = { for name, p in aws_organizations_policy.this : name => p.arn }
}

output "attachments" {
  description = "Bundle/target pairs this module attached."
  value       = keys(aws_organizations_policy_attachment.this)
}
