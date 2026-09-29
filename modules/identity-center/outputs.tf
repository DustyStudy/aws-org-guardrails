output "permission_set_arns" {
  description = "Map of permission set name to ARN."
  value       = { for name, ps in aws_ssoadmin_permission_set.this : name => ps.arn }
}

output "account_assignments" {
  description = "Keys of the account assignments this module manages (permission_set/principal_type/principal_id/account_id)."
  value       = keys(aws_ssoadmin_account_assignment.this)
}
