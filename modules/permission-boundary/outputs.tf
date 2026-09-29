output "policy_arn" {
  description = "ARN of the boundary policy. Attach it as the permissions boundary of workload roles."
  value       = aws_iam_policy.boundary.arn
}

output "policy_name" {
  description = "Name of the boundary policy (for Identity Center customer managed boundary references)."
  value       = aws_iam_policy.boundary.name
}

output "policy_path" {
  description = "Path of the boundary policy."
  value       = aws_iam_policy.boundary.path
}
