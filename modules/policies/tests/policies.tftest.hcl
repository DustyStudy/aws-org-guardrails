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

run "service_specific_credential_statement_is_opt_in" {
  command = plan

  assert {
    condition     = !strcontains(output.scp_policies["core"], "DenyServiceSpecificCredentials")
    error_message = "DenyServiceSpecificCredentials must be opt-in: it can break pipelines that issue these credentials."
  }
}

run "service_specific_credential_statement_is_exempted" {
  command = plan

  variables {
    deny_service_specific_credentials = true
  }

  assert {
    condition = jsonencode(one([
      for s in jsondecode(output.scp_policies["core"]).Statement : s.Condition if s.Sid == "DenyServiceSpecificCredentials"
    ])) == jsonencode({ ArnNotLike = { "aws:PrincipalArn" = var.exempt_principal_arns } })
    error_message = "The service-specific credential deny must carry the standard role exemption."
  }
}

run "imds_hop_limit_statement_is_opt_in" {
  command = plan

  assert {
    condition     = !strcontains(output.scp_policies["data-and-compute"], "RequireImdsHopLimitOne")
    error_message = "RequireImdsHopLimitOne must be opt-in: EKS nodes and other container hosts use a hop limit of 2."
  }
}

run "imds_hop_limit_statement_is_exempted" {
  command = plan

  variables {
    require_imds_hop_limit_one = true
  }

  assert {
    condition = jsonencode(one([
      for s in jsondecode(output.scp_policies["data-and-compute"]).Statement : s.Condition if s.Sid == "RequireImdsHopLimitOne"
      ])) == jsonencode({
      ArnNotLike       = { "aws:PrincipalArn" = var.exempt_principal_arns }
      NumericNotEquals = { "ec2:MetadataHttpPutResponseHopLimit" = "1" }
    })
    error_message = "The hop-limit deny must carry the standard role exemption and require a hop limit of 1."
  }
}

run "athena_results_bucket_statement_is_off_by_default" {
  command = plan

  assert {
    condition     = !strcontains(output.scp_policies["data-and-compute"], "DenyAthenaResultsBucketOutsideOrg")
    error_message = "DenyAthenaResultsBucketOutsideOrg must be opt-in: check S3 data events for outside-org result buckets first."
  }
}

run "athena_results_bucket_statement_keys_on_resource_org" {
  command = plan

  variables {
    deny_athena_results_bucket_outside_org = true
  }

  assert {
    condition = jsonencode(one([
      for s in jsondecode(output.scp_policies["data-and-compute"]).Statement : s.Condition if s.Sid == "DenyAthenaResultsBucketOutsideOrg"
      ])) == jsonencode({
      StringNotEquals = { "aws:ResourceOrgID" = "$${aws:PrincipalOrgID}" }
    })
    error_message = "The Athena deny must apply only to buckets owned outside the caller's organization, with no role exemption."
  }

  assert {
    condition = toset(one([
      for s in jsondecode(output.scp_policies["data-and-compute"]).Statement : s.Resource if s.Sid == "DenyAthenaResultsBucketOutsideOrg"
      ])) == toset([
      "arn:${var.partition}:s3:::aws-athena-query-results-????????????-*",
      "arn:${var.partition}:s3:::aws-athena-query-results-????????????-*/*",
    ])
    error_message = "Only the aws-athena-query-results-<account-id>-<region> name shape and its objects may be in scope."
  }
}

run "kms_network_perimeter_statement_is_off_by_default" {
  command = plan

  assert {
    condition     = !strcontains(output.scp_policies["data-and-compute"], "DenyTaggedKmsKeysOffOrgNetwork")
    error_message = "DenyTaggedKmsKeysOffOrgNetwork must be opt-in: check CloudTrail for calls on tagged keys without a vpcEndpointId first."
  }
}

run "kms_network_perimeter_statement_keys_on_tag_and_org_endpoint" {
  command = plan

  variables {
    deny_tagged_kms_keys_off_org_network = true
  }

  assert {
    condition = jsonencode(one([
      for s in jsondecode(output.scp_policies["data-and-compute"]).Statement : s.Condition if s.Sid == "DenyTaggedKmsKeysOffOrgNetwork"
      ])) == jsonencode({
      ArnNotLike              = { "aws:PrincipalArn" = var.exempt_principal_arns }
      BoolIfExists            = { "aws:PrincipalIsAWSService" = "false", "aws:ViaAWSService" = "false" }
      StringEquals            = { "aws:ResourceTag/guardrails:network-perimeter" = "true" }
      StringNotEqualsIfExists = { "aws:VpceOrgID" = "$${aws:PrincipalOrgID}" }
    })
    error_message = "The KMS deny must cover only tagged keys reached outside an organization VPC endpoint, skip AWS service calls, and carry the role exemption."
  }

  assert {
    condition = one([
      for s in jsondecode(output.scp_policies["data-and-compute"]).Statement : s.Resource if s.Sid == "DenyTaggedKmsKeysOffOrgNetwork"
    ]) == "arn:${var.partition}:kms:*:*:key/*"
    error_message = "Only KMS keys may be in scope, in the configured partition."
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

run "vendor_network_statement_is_opt_in" {
  command = plan

  assert {
    condition     = !strcontains(output.scp_policies["core"], "DenyVendorOffNetwork")
    error_message = "Vendor network statements must only appear for listed vendors."
  }
}

run "vendor_network_statement_keys_on_vendor_principals_and_ranges" {
  command = plan

  variables {
    third_party_vendor_networks = {
      Fireworks = {
        principal_arns = ["arn:aws:iam::*:role/vendor-fireworks-*"]
        source_cidrs   = ["203.0.113.0/24", "2001:db8::/32"]
      }
    }
  }

  assert {
    condition = jsonencode(one([
      for s in jsondecode(output.scp_policies["core"]).Statement : s.Condition if s.Sid == "DenyVendorOffNetworkFireworks"
      ])) == jsonencode({
      ArnLike      = { "aws:PrincipalArn" = ["arn:aws:iam::*:role/vendor-fireworks-*"] }
      ArnNotLike   = { "aws:PrincipalArn" = var.exempt_principal_arns }
      BoolIfExists = { "aws:PrincipalIsAWSService" = "false", "aws:ViaAWSService" = "false" }
      NotIpAddress = { "aws:SourceIp" = ["203.0.113.0/24", "2001:db8::/32"] }
    })
    error_message = "The vendor deny must cover only the vendor's principals off its ranges, skip AWS service calls, and carry the role exemption."
  }
}

run "vendor_principal_cannot_be_every_role" {
  command = plan

  variables {
    third_party_vendor_networks = {
      Fireworks = { principal_arns = ["arn:aws:iam::*:role/*"], source_cidrs = ["203.0.113.0/24"] }
    }
  }

  expect_failures = [var.third_party_vendor_networks]
}

run "vendor_principal_cannot_be_only_wildcards" {
  command = plan

  variables {
    third_party_vendor_networks = {
      Fireworks = { principal_arns = ["arn:aws:iam::*:role/?*"], source_cidrs = ["203.0.113.0/24"] }
    }
  }

  expect_failures = [var.third_party_vendor_networks]
}

run "vendor_principal_must_match_partition" {
  command = plan

  variables {
    third_party_vendor_networks = {
      Fireworks = { principal_arns = ["arn:aws-us-gov:iam::*:role/vendor-fireworks-*"], source_cidrs = ["203.0.113.0/24"] }
    }
  }

  expect_failures = [var.third_party_vendor_networks]
}

run "vendor_range_cannot_be_everything" {
  command = plan

  variables {
    third_party_vendor_networks = {
      Fireworks = { principal_arns = ["arn:aws:iam::*:role/vendor-fireworks-*"], source_cidrs = ["0.0.0.0/0"] }
    }
  }

  expect_failures = [var.third_party_vendor_networks]
}

run "vendor_name_must_fit_a_sid" {
  command = plan

  variables {
    third_party_vendor_networks = {
      "fireworks-ai" = { principal_arns = ["arn:aws:iam::*:role/vendor-fireworks-*"], source_cidrs = ["203.0.113.0/24"] }
    }
  }

  expect_failures = [var.third_party_vendor_networks]
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

run "instance_protection_exemption_must_be_a_protected_role" {
  command = plan

  variables {
    deny_instance_protection_changes          = true
    instance_protection_exempt_principal_arns = ["arn:aws:iam::*:role/platform-deploy"]
  }

  expect_failures = [var.instance_protection_exempt_principal_arns]
}

run "instance_protection_exemption_must_be_a_role_in_the_partition" {
  command = plan

  variables {
    deny_instance_protection_changes          = true
    instance_protection_exempt_principal_arns = ["arn:aws-us-gov:iam::*:role/security-deploy"]
  }

  expect_failures = [var.instance_protection_exempt_principal_arns]
}
