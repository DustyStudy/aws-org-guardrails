output "sns_topic_arn" {
  description = "ARN of the SNS topic used for Bedrock cost alerts."
  value       = aws_sns_topic.cost_alerts.arn
}

output "anomaly_monitor_arn" {
  description = "ARN of the Bedrock cost anomaly monitor."
  value       = aws_ce_anomaly_monitor.bedrock_spend.arn
}

output "budget_name" {
  description = "Name of the Bedrock monthly budget."
  value       = aws_budgets_budget.bedrock_monthly.name
}
