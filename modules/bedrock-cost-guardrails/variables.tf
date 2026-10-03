variable "name_prefix" {
  type        = string
  description = "Prefix used for naming all resources created by this module."
  default     = "bedrock-cost-guardrails"
}

variable "notification_email" {
  type        = string
  description = "Optional email address to subscribe to the SNS topic for cost alerts. Leave empty to skip."
  default     = ""
}

variable "monthly_budget_limit_usd" {
  type        = number
  description = "Monthly USD ceiling for Amazon Bedrock spend. Notifications fire at 80% of actual spend and 100% of forecasted spend."
  default     = 500
}

variable "anomaly_threshold_usd" {
  type        = number
  description = <<-EOT
    Dollar impact threshold above which a detected cost anomaly in Amazon
    Bedrock spend triggers an immediate notification. Cost Anomaly
    Detection uses machine learning against your account's own
    historical spend pattern, so it can catch a spike well before it
    reaches the monthly budget ceiling above.
  EOT
  default     = 50
}
