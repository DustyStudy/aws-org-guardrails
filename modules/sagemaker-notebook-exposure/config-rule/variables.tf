variable "name_prefix" {
  type        = string
  description = "Prefix used for naming all resources created by this module."
  default     = "sagemaker-notebook-config"
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

variable "maximum_execution_frequency" {
  type        = string
  description = "How often AWS Config re-evaluates all notebook instances against this rule."
  default     = "TwentyFour_Hours"

  validation {
    condition = contains(
      ["One_Hour", "Three_Hours", "Six_Hours", "Twelve_Hours", "TwentyFour_Hours"],
      var.maximum_execution_frequency
    )
    error_message = "maximum_execution_frequency must be one of One_Hour, Three_Hours, Six_Hours, Twelve_Hours, TwentyFour_Hours."
  }
}

variable "code_signing_config_arn" {
  type        = string
  description = "Optional ARN of an existing aws_lambda_code_signing_config to enforce on this function. Leave null to skip."
  default     = null
}
