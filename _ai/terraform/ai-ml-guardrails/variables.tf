variable "name_prefix" {
  type        = string
  description = "Prefix used when naming each SCP in Organizations."
  default     = "ai-ml-guardrail"
}

variable "target_ids" {
  type        = list(string)
  description = "OU IDs, account IDs, and/or the org root ID to attach every enabled policy to."
}

variable "enable_deny_disable_bedrock_logging_and_guardrails" {
  type        = bool
  description = "Deny disabling Bedrock model invocation logging or deleting Bedrock Guardrails."
  default     = true
}

variable "enable_restrict_bedrock_foundation_models" {
  type        = bool
  description = <<-EOT
    Restrict bedrock:InvokeModel/InvokeModelWithResponseStream to an
    allow-listed set of foundation models. Off by default - review
    allowed_bedrock_model_patterns before enabling, or every model
    invocation in the account will be denied.
  EOT
  default     = false
}

variable "allowed_bedrock_model_patterns" {
  type        = list(string)
  description = "Foundation-model ID patterns permitted when enable_restrict_bedrock_foundation_models is true (matched against arn:*:bedrock:*::foundation-model/<pattern>)."
  default     = ["anthropic.claude*", "amazon.titan*"]
}

variable "enable_deny_bedrock_long_term_credentials" {
  type        = bool
  description = <<-EOT
    Deny Bedrock model discovery, model access and invocation to IAM users,
    so a leaked access key or Bedrock API key can't be used for LLMjacking.
    Off by default - first confirm in CloudTrail that no workload calls
    Bedrock as an IAM user (userIdentity.type = "IAMUser"), or list the
    ones that must keep working in bedrock_iam_user_exempt_principal_arns.
  EOT
  default     = false
}

variable "bedrock_iam_user_exempt_principal_arns" {
  type        = list(string)
  description = "IAM user ARN patterns still allowed to call Bedrock when enable_deny_bedrock_long_term_credentials is true (e.g. a legacy integration being migrated to a role). Wildcards allowed; keep it short and dated."
  default     = []

  validation {
    condition     = alltrue([for arn in var.bedrock_iam_user_exempt_principal_arns : can(regex("^arn:[^:]+:iam::[^:]+:user/", arn))])
    error_message = "Each exemption must be an IAM user ARN pattern (arn:<partition>:iam::<account>:user/<name>)."
  }
}

variable "enable_lockdown_sagemaker_notebooks" {
  type        = bool
  description = "Deny SageMaker notebook instances with direct internet access, root access, or no VPC."
  default     = true
}

variable "enable_require_sagemaker_encryption" {
  type        = bool
  description = "Deny SageMaker notebook instances and training jobs that don't specify a KMS key."
  default     = true
}
