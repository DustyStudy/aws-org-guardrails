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

run "ses_statement_is_off_by_default" {
  command = plan

  assert {
    condition     = !strcontains(output.scp_policies["core"], "DenySesToIamUsers")
    error_message = "DenySesToIamUsers must be opt-in: SES SMTP senders are IAM users."
  }
}

run "ses_statement_keys_on_iam_users" {
  command = plan

  variables {
    deny_ses_to_iam_users              = true
    ses_iam_user_exempt_principal_arns = ["arn:aws:iam::*:user/ses-smtp-*"]
  }

  assert {
    condition = one([
      for s in jsondecode(output.scp_policies["core"]).Statement : s.Condition if s.Sid == "DenySesToIamUsers"
      ]) == {
      StringEquals = { "aws:PrincipalType" = "User" }
      ArnNotLike   = { "aws:PrincipalArn" = ["arn:aws:iam::*:user/ses-smtp-*"] }
    }
    error_message = "The SES deny must apply to IAM users only, minus the listed SMTP users."
  }
}

run "ses_exemption_must_be_an_iam_user" {
  command = plan

  variables {
    deny_ses_to_iam_users              = true
    ses_iam_user_exempt_principal_arns = ["arn:aws:iam::*:role/mailer"]
  }

  expect_failures = [var.ses_iam_user_exempt_principal_arns]
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

run "rejects_exempt_roles_that_are_not_protected" {
  command = plan

  variables {
    # Anyone could create a role named "admin" and inherit the exemption.
    exempt_principal_arns = ["arn:aws:iam::*:role/admin"]
  }

  expect_failures = [var.exempt_principal_arns]
}

run "accepts_exempt_roles_under_a_custom_protected_prefix" {
  command = plan

  variables {
    exempt_principal_arns        = ["arn:aws:iam::*:role/ProwlerScan", "arn:aws:iam::*:role/stacksets-exec-*"]
    protected_role_name_prefixes = ["OrganizationAccountAccessRole", "security-", "ProwlerScan", "stacksets-exec-"]
  }

  assert {
    condition     = strcontains(output.scp_policies["core"], "role/stacksets-exec-*")
    error_message = "Custom protected prefixes should render into the protected-role statement."
  }
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

run "rejects_non_service_principals_for_service_linked_roles" {
  command = plan

  variables {
    service_linked_role_services = ["ecs"]
  }

  expect_failures = [var.service_linked_role_services]
}
