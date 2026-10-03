variable "name_prefix" {
  type        = string
  description = "Prefix used for naming all resources created by this module."
  default     = "bedrock-logging-enforcement"
}

variable "notification_email" {
  type        = string
  description = "Optional email address to subscribe to the SNS topic. Leave empty to skip."
  default     = ""
}

variable "schedule_expression" {
  type        = string
  description = "EventBridge schedule expression controlling how often the check runs."
  default     = "rate(1 day)"
}

variable "log_text_data" {
  type        = bool
  description = "Log text prompts/completions."
  default     = true
}

variable "log_image_data" {
  type        = bool
  description = "Log image inputs/outputs (can be large - consider cost/storage before enabling)."
  default     = false
}

variable "log_embedding_data" {
  type        = bool
  description = "Log embedding inputs."
  default     = false
}

variable "code_signing_config_arn" {
  type        = string
  description = "Optional ARN of an existing aws_lambda_code_signing_config to enforce on this function. Leave null to skip."
  default     = null
}
