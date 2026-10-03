variable "name_prefix" {
  type        = string
  description = "Prefix used for naming all resources created by this module."
  default     = "sagemaker-notebook-exposure"
}

variable "notification_email" {
  type        = string
  description = "Optional email address to subscribe to the SNS topic. Leave empty to skip."
  default     = ""
}

variable "auto_restart" {
  type        = bool
  description = "Restart the notebook automatically after remediation completes. Default false - leaves it stopped for review."
  default     = false
}

variable "code_signing_config_arn" {
  type        = string
  description = "Optional ARN of an existing aws_lambda_code_signing_config to enforce on this function. Leave null to skip."
  default     = null
}
