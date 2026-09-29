variable "instance_arn" {
  description = "ARN of the IAM Identity Center instance (arn:<partition>:sso:::instance/ssoins-...)."
  type        = string

  validation {
    condition     = can(regex("^arn:aws(-us-gov|-cn)?:sso:::instance/ssoins-[0-9a-f]{16}$", var.instance_arn))
    error_message = "instance_arn must look like arn:aws:sso:::instance/ssoins-0123456789abcdef."
  }
}

variable "permission_sets" {
  description = <<-EOT
    Permission sets keyed by name. Each one takes AWS managed policies, customer
    managed policies (referenced by name, so they must exist in every assigned
    account), an optional inline policy and a permissions boundary.
  EOT
  type = map(object({
    description         = string
    session_duration    = optional(string, "PT1H")
    relay_state         = optional(string)
    managed_policy_arns = optional(list(string), [])
    customer_managed_policies = optional(list(object({
      name = string
      path = optional(string, "/")
    })), [])
    inline_policy = optional(string)
    permissions_boundary = optional(object({
      customer_managed_policy = optional(object({
        name = string
        path = optional(string, "/")
      }))
      managed_policy_arn = optional(string)
    }))
  }))

  validation {
    condition     = alltrue([for name, _ in var.permission_sets : can(regex("^[A-Za-z0-9+=,.@-]{1,32}$", name))])
    error_message = "Permission set names must be 1-32 characters of letters, digits and +=,.@-."
  }

  validation {
    # ISO 8601 hours, 1 to 12, which is the range Identity Center accepts.
    condition = alltrue([
      for ps in values(var.permission_sets) :
      can(regex("^PT([1-9]|1[0-2])H$", ps.session_duration))
    ])
    error_message = "session_duration must be between PT1H and PT12H, in whole hours."
  }

  validation {
    condition = alltrue([
      for ps in values(var.permission_sets) :
      ps.permissions_boundary == null ? true : (
        (ps.permissions_boundary.customer_managed_policy != null) != (ps.permissions_boundary.managed_policy_arn != null)
      )
    ])
    error_message = "A permissions_boundary sets exactly one of customer_managed_policy or managed_policy_arn."
  }
}

variable "require_permissions_boundary" {
  description = "Refuse to create a permission set without a permissions boundary, unless it is listed in boundary_exempt_permission_sets."
  type        = bool
  default     = true
}

variable "boundary_exempt_permission_sets" {
  description = "Permission sets allowed to have no boundary, such as a break-glass administrator. Keep this list short and reviewed."
  type        = set(string)
  default     = []
}

variable "account_assignments" {
  description = "Who gets which permission set in which account. principal_id is the Identity Store group or user ID."
  type = list(object({
    permission_set = string
    principal_type = optional(string, "GROUP")
    principal_id   = string
    account_id     = string
  }))
  default = []

  validation {
    condition     = alltrue([for a in var.account_assignments : contains(keys(var.permission_sets), a.permission_set)])
    error_message = "Every account assignment must reference a permission set defined in permission_sets."
  }

  validation {
    condition     = alltrue([for a in var.account_assignments : contains(["GROUP", "USER"], a.principal_type)])
    error_message = "principal_type must be GROUP or USER."
  }

  validation {
    condition     = alltrue([for a in var.account_assignments : can(regex("^[0-9]{12}$", a.account_id))])
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "tags" {
  description = "Tags applied to every permission set."
  type        = map(string)
  default     = {}
}
