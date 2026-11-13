data "aws_partition" "current" {}

module "policies" {
  source = "../policies"

  partition                    = data.aws_partition.current.partition
  exempt_principal_arns        = var.exempt_principal_arns
  allowed_regions              = var.allowed_regions
  enable_region_restriction    = var.enable_region_restriction
  deny_iam_user_credentials    = var.deny_iam_user_credentials
  protected_role_name_prefixes = var.protected_role_name_prefixes

  deny_service_specific_credentials      = var.deny_service_specific_credentials
  require_imds_hop_limit_one             = var.require_imds_hop_limit_one
  deny_athena_results_bucket_outside_org = var.deny_athena_results_bucket_outside_org
  deny_instance_protection_changes       = var.deny_instance_protection_changes

  instance_protection_exempt_principal_arns = var.instance_protection_exempt_principal_arns
  deny_tagged_kms_keys_off_org_network      = var.deny_tagged_kms_keys_off_org_network

  deny_ses_to_iam_users              = var.deny_ses_to_iam_users
  ses_iam_user_exempt_principal_arns = var.ses_iam_user_exempt_principal_arns

  third_party_vendor_networks = var.third_party_vendor_networks
}

locals {
  available = module.policies.scp_policies
  enabled   = var.enabled_bundles == null ? toset(keys(local.available)) : var.enabled_bundles

  bundles = { for name in local.enabled : name => local.available[name] if contains(keys(local.available), name) }

  attachments = {
    for pair in setproduct(keys(local.bundles), var.target_ids) :
    "${pair[0]}/${pair[1]}" => { bundle = pair[0], target_id = pair[1] }
  }

  descriptions = {
    core                 = "Organization membership, root user, IAM user credentials and protected roles."
    "security-services"  = "Stops workloads from disabling CloudTrail, Config, GuardDuty, Security Hub and Access Analyzer."
    "data-and-compute"   = "EBS default encryption, account-level S3 public access block and IMDSv2."
    "region-restriction" = "Denies regional services outside the allowed regions."
  }
}

resource "aws_organizations_policy" "this" {
  for_each = local.bundles

  name        = "${var.name_prefix}-${each.key}"
  description = local.descriptions[each.key]
  type        = "SERVICE_CONTROL_POLICY"
  content     = each.value
  tags        = var.tags

  lifecycle {
    precondition {
      condition     = length(setsubtract(local.enabled, keys(local.available))) == 0
      error_message = "enabled_bundles names a bundle that does not exist or is turned off: ${join(", ", setsubtract(local.enabled, keys(local.available)))}. Available: ${join(", ", keys(local.available))}."
    }

    precondition {
      condition     = length(local.bundles) + var.other_scps_per_target <= var.max_scps_per_target
      error_message = "Attaching ${length(local.bundles)} bundles to targets that already hold ${var.other_scps_per_target} SCPs exceeds max_scps_per_target (${var.max_scps_per_target}). Disable a bundle, attach some at a parent OU, or set max_scps_per_target to 10 (AWS's current quota)."
    }
  }
}

resource "aws_organizations_policy_attachment" "this" {
  for_each = local.attachments

  policy_id = aws_organizations_policy.this[each.value.bundle].id
  target_id = each.value.target_id
}
