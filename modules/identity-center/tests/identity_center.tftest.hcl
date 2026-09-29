mock_provider "aws" {}

variables {
  instance_arn = "arn:aws:sso:::instance/ssoins-0123456789abcdef"

  permission_sets = {
    Developer = {
      description         = "Workload engineers"
      managed_policy_arns = ["arn:aws:iam::aws:policy/PowerUserAccess"]
      permissions_boundary = {
        customer_managed_policy = { name = "workload-permissions-boundary" }
      }
    }
    ReadOnly = {
      description         = "Auditors"
      session_duration    = "PT4H"
      managed_policy_arns = ["arn:aws:iam::aws:policy/ReadOnlyAccess", "arn:aws:iam::aws:policy/SecurityAudit"]
      permissions_boundary = {
        managed_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
      }
    }
  }

  account_assignments = [
    { permission_set = "Developer", principal_id = "9067c1a2b3-1f2e3d4c-5b6a-4789-8a7b-6c5d4e3f2a1b", account_id = "111122223333" },
    { permission_set = "ReadOnly", principal_id = "9067c1a2b3-2a3b4c5d-6e7f-4801-9b2c-3d4e5f6a7b8c", account_id = "111122223333" },
    { permission_set = "ReadOnly", principal_id = "9067c1a2b3-2a3b4c5d-6e7f-4801-9b2c-3d4e5f6a7b8c", account_id = "444455556666" },
  ]
}

run "creates_sets_policies_boundaries_and_assignments" {
  command = plan

  assert {
    condition     = length(aws_ssoadmin_permission_set.this) == 2
    error_message = "Expected two permission sets."
  }

  assert {
    condition     = length(aws_ssoadmin_managed_policy_attachment.this) == 3
    error_message = "Expected one managed policy on Developer and two on ReadOnly."
  }

  assert {
    condition     = length(aws_ssoadmin_permissions_boundary_attachment.this) == 2
    error_message = "Both permission sets should get a boundary."
  }

  assert {
    condition     = aws_ssoadmin_permissions_boundary_attachment.this["Developer"].permissions_boundary[0].customer_managed_policy_reference[0].name == "workload-permissions-boundary"
    error_message = "Developer should use the customer managed boundary."
  }

  assert {
    condition     = length(aws_ssoadmin_account_assignment.this) == 3
    error_message = "Expected three account assignments."
  }

  assert {
    condition     = aws_ssoadmin_permission_set.this["Developer"].session_duration == "PT1H"
    error_message = "Sessions should default to one hour."
  }
}

run "refuses_permission_sets_without_a_boundary" {
  command = plan

  variables {
    permission_sets = {
      Admin = {
        description         = "Unbounded"
        managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]
      }
    }
    account_assignments = []
  }

  expect_failures = [aws_ssoadmin_permission_set.this]
}

run "allows_a_listed_break_glass_set_without_a_boundary" {
  command = plan

  variables {
    permission_sets = {
      BreakGlass = {
        description         = "Emergency access; alarmed on use"
        managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]
      }
    }
    boundary_exempt_permission_sets = ["BreakGlass"]
    account_assignments             = []
  }

  assert {
    condition     = length(aws_ssoadmin_permissions_boundary_attachment.this) == 0
    error_message = "BreakGlass should have no boundary attachment."
  }
}

run "rejects_assignments_to_unknown_permission_sets" {
  command = plan

  variables {
    account_assignments = [{ permission_set = "Typo", principal_id = "9067c1a2b3-1f2e3d4c-5b6a-4789-8a7b-6c5d4e3f2a1b", account_id = "111122223333" }]
  }

  expect_failures = [var.account_assignments]
}

run "rejects_sessions_longer_than_twelve_hours" {
  command = plan

  variables {
    permission_sets = {
      Developer = {
        description      = "Too long"
        session_duration = "PT24H"
        permissions_boundary = {
          managed_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
        }
      }
    }
    account_assignments = []
  }

  expect_failures = [var.permission_sets]
}

run "rejects_a_boundary_with_both_kinds_set" {
  command = plan

  variables {
    permission_sets = {
      Developer = {
        description = "Ambiguous"
        permissions_boundary = {
          customer_managed_policy = { name = "workload-permissions-boundary" }
          managed_policy_arn      = "arn:aws:iam::aws:policy/ReadOnlyAccess"
        }
      }
    }
    account_assignments = []
  }

  expect_failures = [var.permission_sets]
}
