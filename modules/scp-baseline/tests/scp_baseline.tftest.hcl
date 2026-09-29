# Plan-only tests. The mocked provider keeps them offline: no credentials,
# no organization, nothing is created.

mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }
}

variables {
  target_ids            = ["ou-ab12-cdefgh34", "123456789012"]
  exempt_principal_arns = ["arn:aws:iam::*:role/security-breakglass"]
}

run "all_bundles_attach_to_every_target" {
  command = plan

  assert {
    condition     = length(aws_organizations_policy.this) == 4
    error_message = "Expected 4 SCP bundles by default."
  }

  assert {
    condition     = length(aws_organizations_policy_attachment.this) == 8
    error_message = "Expected 4 bundles x 2 targets = 8 attachments."
  }

  assert {
    condition     = alltrue([for p in aws_organizations_policy.this : p.type == "SERVICE_CONTROL_POLICY"])
    error_message = "Every policy must be a service control policy."
  }

  assert {
    condition     = aws_organizations_policy.this["core"].name == "guardrails-core"
    error_message = "Policy names should be <name_prefix>-<bundle>."
  }
}

run "region_restriction_can_be_turned_off" {
  command = plan

  variables {
    enable_region_restriction = false
  }

  assert {
    condition     = !contains(keys(aws_organizations_policy.this), "region-restriction")
    error_message = "region-restriction bundle should not exist when disabled."
  }
}

run "subset_of_bundles" {
  command = plan

  variables {
    enabled_bundles = ["core", "security-services"]
  }

  assert {
    condition     = toset(keys(aws_organizations_policy.this)) == toset(["core", "security-services"])
    error_message = "Only the requested bundles should be created."
  }
}

run "govcloud_partition_flows_into_the_policies" {
  command = plan

  override_data {
    target = data.aws_partition.current
    values = {
      partition = "aws-us-gov"
    }
  }

  variables {
    exempt_principal_arns = ["arn:aws-us-gov:iam::*:role/security-breakglass"]
    allowed_regions       = ["us-gov-west-1"]
  }

  assert {
    condition     = strcontains(aws_organizations_policy.this["core"].content, "arn:aws-us-gov:iam::*:root")
    error_message = "The root-user deny must use the GovCloud partition."
  }
}

run "refuses_to_exceed_five_scps_per_target" {
  command = plan

  variables {
    other_scps_per_target = 2
  }

  expect_failures = [aws_organizations_policy.this]
}

run "rejects_unknown_bundle_names" {
  command = plan

  variables {
    enabled_bundles = ["core", "no-such-bundle"]
  }

  expect_failures = [aws_organizations_policy.this]
}

run "rejects_malformed_target_ids" {
  command = plan

  variables {
    target_ids = ["prod-ou"]
  }

  expect_failures = [var.target_ids]
}

run "requires_an_exempt_principal" {
  command = plan

  variables {
    exempt_principal_arns = []
  }

  expect_failures = [var.exempt_principal_arns]
}
