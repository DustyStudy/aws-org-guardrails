variable "partition" {
  description = "AWS partition the policies are rendered for: aws, aws-us-gov or aws-cn."
  type        = string
  default     = "aws"

  validation {
    condition     = contains(["aws", "aws-us-gov", "aws-cn"], var.partition)
    error_message = "partition must be one of aws, aws-us-gov or aws-cn."
  }
}

variable "exempt_principal_arns" {
  description = <<-EOT
    IAM role ARN patterns (wildcards allowed) that the SCP bundles do not apply
    to: typically a break-glass role and the pipeline role that manages
    security services. Use "*" for the account ID so one pattern covers every
    member account, e.g. arn:aws:iam::*:role/security-breakglass.
    Required for the SCP bundles; leave null to render only the permissions
    boundary (scp_policies is then empty).
  EOT
  type        = list(string)
  default     = null

  # An empty list would render SCPs with no escape hatch at all, so even the
  # team that owns the guardrails could not repair a broken CloudTrail trail.
  validation {
    condition     = var.exempt_principal_arns == null ? true : length(var.exempt_principal_arns) > 0
    error_message = "exempt_principal_arns needs at least one role (for example a break-glass role)."
  }

  validation {
    condition = var.exempt_principal_arns == null ? true : alltrue([
      for arn in var.exempt_principal_arns :
      can(regex("^arn:aws(-us-gov|-cn)?:iam::([*]|[0-9]{12}):role/.+$", arn))
    ])
    error_message = "Each exempt principal must be an IAM role ARN pattern such as arn:aws:iam::*:role/security-breakglass."
  }

  validation {
    condition = var.exempt_principal_arns == null ? true : alltrue([
      for arn in var.exempt_principal_arns : split(":", arn)[1] == var.partition
    ])
    error_message = "Every exempt principal ARN must use the same partition as var.partition."
  }

  # The exemption matches roles by name. If anyone could create or change a
  # role with that name, they could give themselves the exemption. Requiring
  # each exempt role to fall under a protected prefix (which denies
  # iam:CreateRole and every change to the role) closes that path.
  validation {
    condition = var.exempt_principal_arns == null ? true : alltrue([
      for arn in var.exempt_principal_arns : anytrue([
        for prefix in var.protected_role_name_prefixes :
        startswith(element(split(":role/", arn), 1), prefix)
      ])
    ])
    error_message = "Every exempt role name must start with one of protected_role_name_prefixes, or anyone could create a role with that name and inherit the exemption."
  }
}

variable "allowed_regions" {
  description = "Regions workloads may use. Requests to regional services anywhere else are denied."
  type        = list(string)
  default     = ["us-east-1", "us-west-2"]

  validation {
    condition     = length(var.allowed_regions) > 0
    error_message = "allowed_regions must name at least one region."
  }

  validation {
    condition = alltrue([
      for r in var.allowed_regions : can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]$", r))
    ])
    error_message = "allowed_regions entries must be region codes such as us-east-1 or us-gov-west-1."
  }

  validation {
    condition = alltrue([
      for r in var.allowed_regions : (var.partition == "aws-us-gov") == startswith(r, "us-gov-")
    ])
    error_message = "GovCloud (aws-us-gov) accepts only us-gov-* regions, and us-gov-* regions need partition aws-us-gov."
  }
}

variable "enable_region_restriction" {
  description = "Render the region-restriction SCP bundle."
  type        = bool
  default     = true
}

variable "deny_iam_user_credentials" {
  description = "Deny creating IAM users, access keys and console passwords. Humans use IAM Identity Center; workloads use roles."
  type        = bool
  default     = true
}

variable "protected_role_name_prefixes" {
  description = "Role name prefixes that only exempt principals may modify or delete (the org access role, security tooling roles and so on)."
  type        = list(string)
  default     = ["OrganizationAccountAccessRole", "security-"]

  validation {
    condition     = alltrue([for p in var.protected_role_name_prefixes : length(trimspace(p)) > 0])
    error_message = "protected_role_name_prefixes entries cannot be empty; an empty prefix would protect every role."
  }
}

variable "boundary_policy_name" {
  description = "Name of the customer managed policy used as the permissions boundary. Must match the name the permission-boundary module creates in each account."
  type        = string
  default     = "workload-permissions-boundary"
}

variable "boundary_policy_path" {
  description = "IAM path of the permissions boundary policy."
  type        = string
  default     = "/"

  validation {
    condition     = startswith(var.boundary_policy_path, "/") && endswith(var.boundary_policy_path, "/")
    error_message = "boundary_policy_path must start and end with a slash."
  }
}

variable "delegated_role_path" {
  description = "IAM path under which boundary-bound principals may create, change and pass roles."
  type        = string
  default     = "/workload/"

  validation {
    condition     = startswith(var.delegated_role_path, "/") && endswith(var.delegated_role_path, "/") && var.delegated_role_path != "/"
    error_message = "delegated_role_path must start and end with a slash and cannot be \"/\" (that would include every role)."
  }
}

variable "service_linked_role_services" {
  description = <<-EOT
    Service principals for which boundary-bound principals may create
    service-linked roles, such as ecs.amazonaws.com. A team adopting a service
    that needs a new service-linked role either adds it here or asks the
    platform team to create the role once per account.
  EOT
  type        = list(string)
  default = [
    "autoscaling.amazonaws.com",
    "ecs.amazonaws.com",
    "eks.amazonaws.com",
    "eks-nodegroup.amazonaws.com",
    "elasticache.amazonaws.com",
    "elasticloadbalancing.amazonaws.com",
    "rds.amazonaws.com",
    "spot.amazonaws.com",
  ]
  nullable = false

  validation {
    condition     = alltrue([for s in var.service_linked_role_services : can(regex("^[a-z0-9.-]+[.]amazonaws[.]com$", s))])
    error_message = "service_linked_role_services entries must be service principals such as ecs.amazonaws.com."
  }
}
