variable "target_ids" {
  description = "Organization root, OU or account IDs to attach every enabled bundle to (r-xxxx, ou-xxxx-xxxxxxxx or a 12-digit account ID)."
  type        = list(string)

  validation {
    condition     = length(var.target_ids) > 0
    error_message = "target_ids must name at least one root, OU or account."
  }

  validation {
    condition = alltrue([
      for id in var.target_ids : can(regex("^(r-[0-9a-z]{4,32}|ou-[0-9a-z]{4,32}-[0-9a-z]{8,32}|[0-9]{12})$", id))
    ])
    error_message = "Each target must be a root (r-...), OU (ou-...-...) or 12-digit account ID."
  }
}

variable "enabled_bundles" {
  description = "SCP bundles to create and attach. Leave null for all of them."
  type        = set(string)
  default     = null
}

variable "other_scps_per_target" {
  description = <<-EOT
    SCPs already attached directly to each target outside this module
    (FullAWSAccess counts as one). AWS allows 5 per target, so this module
    refuses to plan an attachment that would go over the limit.
  EOT
  type        = number
  default     = 1

  validation {
    condition     = var.other_scps_per_target >= 0 && floor(var.other_scps_per_target) == var.other_scps_per_target
    error_message = "other_scps_per_target must be a whole number, zero or more."
  }
}

variable "name_prefix" {
  description = "Prefix for the SCP names."
  type        = string
  default     = "guardrails"
}

variable "tags" {
  description = "Tags applied to every SCP."
  type        = map(string)
  default     = {}
}

# Passed through to the policies module; see modules/policies/variables.tf.

variable "exempt_principal_arns" {
  description = "IAM role ARN patterns the guardrails do not apply to (break-glass and security pipeline roles)."
  type        = list(string)

  # Checked here as well as in the policies module so the error points at
  # this module's input.
  validation {
    condition     = length(var.exempt_principal_arns) > 0
    error_message = "exempt_principal_arns needs at least one role (for example a break-glass role)."
  }
}

variable "allowed_regions" {
  description = "Regions workloads may use."
  type        = list(string)
  default     = ["us-east-1", "us-west-2"]
}

variable "enable_region_restriction" {
  description = "Create the region-restriction bundle."
  type        = bool
  default     = true
}

variable "deny_iam_user_credentials" {
  description = "Deny creating IAM users, access keys and console passwords."
  type        = bool
  default     = true
}

variable "protected_role_name_prefixes" {
  description = "Role name prefixes only exempt principals may change."
  type        = list(string)
  default     = ["OrganizationAccountAccessRole", "security-"]
}
