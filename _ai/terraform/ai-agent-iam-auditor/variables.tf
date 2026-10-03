variable "name_prefix" {
  type        = string
  description = "Prefix used for naming all resources created by this module."
  default     = "ai-agent-iam-auditor"
}

variable "notification_email" {
  type        = string
  description = "Optional email address to subscribe to the SNS topic. Leave empty to skip."
  default     = ""
}

variable "schedule_expression" {
  type        = string
  description = "EventBridge schedule expression controlling how often the audit runs."
  default     = "rate(1 day)"
}

variable "ai_service_principals" {
  type        = list(string)
  description = "Trust-policy service principals to treat as \"AI/agent\" roles."
  default     = ["bedrock.amazonaws.com", "sagemaker.amazonaws.com", "q.amazonaws.com", "qbusiness.amazonaws.com"]
}

variable "sensitive_wildcard_services" {
  type        = list(string)
  description = "IAM service prefixes where \"<service>:*\" combined with Resource \"*\" is flagged as over-broad."
  default     = ["iam", "ec2", "s3", "kms", "organizations", "sts"]
}

variable "check_bedrock_agent_action_groups" {
  type        = bool
  description = <<-EOT
    Also discover and audit the Lambda execution roles behind every
    Bedrock Agent's action groups, not just roles whose trust policy
    directly names an AI service. This is usually the higher-risk role
    of the two, since it's what actually executes when the agent decides
    to act. Only the DRAFT version of each agent is checked.
  EOT
  default     = true
}

variable "code_signing_config_arn" {
  type        = string
  description = "Optional ARN of an existing aws_lambda_code_signing_config to enforce on this function. Leave null to skip."
  default     = null
}
