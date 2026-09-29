# Permissions boundary for principals that application teams and pipelines
# create in their own accounts.
#
# The boundary allows everything and then removes the paths to privilege
# escalation. Identity policies still decide what a principal can actually
# do; the boundary only caps it. No ARN contains a literal account ID, so
# one rendered document works in every member account:
#
# * Resource and NotResource ARNs use "*" for the account. IAM API calls only
#   ever act on the caller's own account, so this matches exactly the same
#   resources. (IAM's CreatePolicy rejects a policy variable in the account
#   field of a resource ARN with "failed legacy parsing", even though IAM
#   Access Analyzer and the policy simulator accept it.)
# * The iam:PermissionsBoundary condition needs the exact ARN, and policy
#   variables are allowed in condition values, so it uses
#   ${aws:PrincipalAccount}.

locals {
  boundary_path_and_name = "policy${var.boundary_policy_path}${var.boundary_policy_name}"

  boundary_arn           = "arn:${local.p}:iam::*:${local.boundary_path_and_name}"
  boundary_condition_arn = "arn:${local.p}:iam::$${aws:PrincipalAccount}:${local.boundary_path_and_name}"
  delegated_arn          = "arn:${local.p}:iam::*:role${var.delegated_role_path}*"
  slr_arns = [
    for service in var.service_linked_role_services :
    "arn:${local.p}:iam::*:role/aws-service-role/${service}/*"
  ]

  boundary_statements = [
    {
      # A boundary is a ceiling, not a grant, so a broad Allow is safe here:
      # the Deny statements below carve out the escalation paths. PassRole and
      # service-linked role creation are left out of the broad Allow and
      # granted on scoped resources instead, so the Allow is safe on its own
      # and IAM Access Analyzer reports no findings for it.
      Sid       = "AllowWithinBoundary"
      Effect    = "Allow"
      NotAction = ["iam:PassRole", "iam:CreateServiceLinkedRole"]
      Resource  = "*"
    },
    {
      Sid      = "AllowPassDelegatedRoles"
      Effect   = "Allow"
      Action   = "iam:PassRole"
      Resource = local.delegated_arn
    },
    {
      Sid      = "AllowServiceLinkedRoles"
      Effect   = "Allow"
      Action   = "iam:CreateServiceLinkedRole"
      Resource = local.slr_arns
    },
    {
      # A principal inside the boundary can only create principals that are
      # also inside it, so the boundary cannot be escaped by making a new role.
      Sid    = "DenyPrincipalsWithoutThisBoundary"
      Effect = "Deny"
      Action = [
        "iam:CreateRole",
        "iam:CreateUser",
        "iam:PutRolePermissionsBoundary",
        "iam:PutUserPermissionsBoundary",
      ]
      Resource = "*"
      Condition = {
        StringNotEquals = { "iam:PermissionsBoundary" = local.boundary_condition_arn }
      }
    },
    {
      Sid    = "DenyBoundaryRemoval"
      Effect = "Deny"
      Action = [
        "iam:DeleteRolePermissionsBoundary",
        "iam:DeleteUserPermissionsBoundary",
      ]
      Resource = "*"
    },
    {
      Sid    = "DenyBoundaryPolicyChanges"
      Effect = "Deny"
      Action = [
        "iam:CreatePolicyVersion",
        "iam:DeletePolicy",
        "iam:DeletePolicyVersion",
        "iam:SetDefaultPolicyVersion",
      ]
      Resource = local.boundary_arn
    },
    {
      # Roles outside the delegated path (admin roles, security tooling) can
      # be neither changed nor handed to a service via PassRole.
      Sid    = "DenyRoleChangesOutsideDelegatedPath"
      Effect = "Deny"
      Action = [
        "iam:AttachRolePolicy",
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:DeleteRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PassRole",
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy",
      ]
      NotResource = local.delegated_arn
    },
    {
      Sid      = "DenyOrganizationAndAccountSettings"
      Effect   = "Deny"
      Action   = ["organizations:*", "account:*"]
      Resource = "*"
    },
  ]

  permissions_boundary_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = local.boundary_statements
  })
}
