variable "policy_name" {
  description = "Name of the boundary policy. Every account should use the same name so the rendered policy can find itself."
  type        = string
  default     = "workload-permissions-boundary"
}

variable "policy_path" {
  description = "IAM path of the boundary policy."
  type        = string
  default     = "/"
}

variable "delegated_role_path" {
  description = "IAM path under which boundary-bound principals may create, change and pass roles."
  type        = string
  default     = "/workload/"
}

variable "tags" {
  description = "Tags applied to the policy."
  type        = map(string)
  default     = {}
}
