# Input validation tests. Rendered policy behavior is tested in Python
# (tests/test_scps.py, tests/test_boundary.py), which evaluates the JSON.

variables {
  exempt_principal_arns = ["arn:aws:iam::*:role/security-breakglass"]
}

run "defaults_render_four_bundles" {
  command = plan

  assert {
    condition     = toset(keys(output.scp_policies)) == toset(["core", "security-services", "data-and-compute", "region-restriction"])
    error_message = "Unexpected bundle set."
  }
}

run "iam_user_statement_is_optional" {
  command = plan

  variables {
    deny_iam_user_credentials = false
  }

  assert {
    condition     = !strcontains(output.scp_policies["core"], "DenyIamUserCredentials")
    error_message = "DenyIamUserCredentials should be absent when disabled."
  }
}

run "boundary_references_itself_by_account_variable" {
  command = plan

  variables {
    boundary_policy_path = "/guardrails/"
  }

  assert {
    condition     = output.boundary_policy_arn_template == "arn:aws:iam::$${aws:PrincipalAccount}:policy/guardrails/workload-permissions-boundary"
    error_message = "Boundary ARN template is wrong."
  }
}

run "rejects_exempt_principals_from_another_partition" {
  command = plan

  variables {
    partition = "aws-us-gov"
    # Regions are valid for GovCloud so only the principal check can fail.
    allowed_regions = ["us-gov-west-1"]
  }

  expect_failures = [var.exempt_principal_arns]
}

run "rejects_commercial_regions_in_govcloud" {
  command = plan

  variables {
    partition             = "aws-us-gov"
    exempt_principal_arns = ["arn:aws-us-gov:iam::*:role/security-breakglass"]
    allowed_regions       = ["us-east-1"]
  }

  expect_failures = [var.allowed_regions]
}

run "rejects_non_role_exempt_principals" {
  command = plan

  variables {
    exempt_principal_arns = ["arn:aws:iam::*:user/admin"]
  }

  expect_failures = [var.exempt_principal_arns]
}

run "rejects_root_delegated_path" {
  command = plan

  variables {
    delegated_role_path = "/"
  }

  expect_failures = [var.delegated_role_path]
}

run "rejects_empty_protected_prefix" {
  command = plan

  variables {
    protected_role_name_prefixes = [""]
  }

  expect_failures = [var.protected_role_name_prefixes]
}

run "boundary_only_render_when_no_exempt_principals" {
  command = plan

  variables {
    exempt_principal_arns = null
  }

  assert {
    condition     = length(output.scp_policies) == 0 && length(output.permissions_boundary_policy) > 0
    error_message = "Without exempt principals only the boundary should render."
  }
}
