mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }
}

run "creates_the_boundary_policy" {
  command = plan

  assert {
    condition     = aws_iam_policy.boundary.name == "workload-permissions-boundary" && aws_iam_policy.boundary.path == "/"
    error_message = "Unexpected policy name or path."
  }

  assert {
    condition     = contains([for s in jsondecode(aws_iam_policy.boundary.policy).Statement : s.Sid], "DenyPrincipalsWithoutThisBoundary")
    error_message = "Boundary must stop principals from creating roles without the boundary."
  }
}

run "boundary_points_at_its_own_name_and_path" {
  command = plan

  variables {
    policy_name = "team-boundary"
    policy_path = "/guardrails/"
  }

  assert {
    condition     = strcontains(aws_iam_policy.boundary.policy, "policy/guardrails/team-boundary")
    error_message = "The self-reference must follow policy_name and policy_path, or the boundary would not protect itself."
  }
}

run "delegated_path_scopes_role_management" {
  command = plan

  variables {
    delegated_role_path = "/apps/"
  }

  assert {
    condition = one([
      for s in jsondecode(aws_iam_policy.boundary.policy).Statement : s.NotResource
      if s.Sid == "DenyRoleChangesOutsideDelegatedPath"
    ]) == "arn:aws:iam::*:role/apps/*"
    error_message = "Role management must be limited to the delegated path."
  }
}

run "service_linked_roles_follow_the_input" {
  command = plan

  variables {
    service_linked_role_services = ["ecs.amazonaws.com"]
  }

  assert {
    condition = one([
      for s in jsondecode(aws_iam_policy.boundary.policy).Statement : s.Resource
      if s.Sid == "AllowServiceLinkedRoles"
    ]) == ["arn:aws:iam::*:role/aws-service-role/ecs.amazonaws.com/*"]
    error_message = "Service-linked role creation must be scoped to the listed services."
  }
}
