# Service control policies, grouped into bundles.
#
# AWS allows at most 5 SCPs attached directly to a root, OU or account, and
# FullAWSAccess usually takes one slot. Grouping related statements into four
# bundles leaves room for it while keeping each bundle focused enough to
# review on its own. Each bundle must also stay under the 5,120 character SCP
# size limit; tests/test_scps.py checks both limits on every render.
#
# Every statement is a Deny. Allow comes from FullAWSAccess (or whatever
# allow-list SCPs the organization already uses), so these bundles only
# remove permissions and never grant any.

locals {
  p = var.partition

  # Most statements carry this condition so the break-glass and security
  # pipeline roles can still repair what the guardrail protects.
  exempt = {
    ArnNotLike = { "aws:PrincipalArn" = var.exempt_principal_arns }
  }

  protected_role_arns = [
    for prefix in var.protected_role_name_prefixes : "arn:${local.p}:iam::*:role/${prefix}*"
  ]

  core_statements = concat(
    [
      {
        # No exemption: nobody in a member account should be able to take it
        # out of the organization and away from every other guardrail.
        Sid      = "DenyLeaveOrganization"
        Effect   = "Deny"
        Action   = ["organizations:LeaveOrganization"]
        Resource = "*"
      },
      {
        Sid       = "DenyRegionOptInChanges"
        Effect    = "Deny"
        Action    = ["account:EnableRegion", "account:DisableRegion"]
        Resource  = "*"
        Condition = local.exempt
      },
      {
        # SCPs do apply to a member account's root user. Root is needed only
        # for a short list of tasks, which the management account can do with
        # centralized root access instead.
        Sid      = "DenyRootUser"
        Effect   = "Deny"
        Action   = ["*"]
        Resource = "*"
        Condition = {
          ArnLike = { "aws:PrincipalArn" = "arn:${local.p}:iam::*:root" }
        }
      },
      {
        Sid    = "DenyProtectedRoleChanges"
        Effect = "Deny"
        Action = [
          "iam:AttachRolePolicy",
          "iam:DeleteRole",
          "iam:DeleteRolePermissionsBoundary",
          "iam:DeleteRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PutRolePermissionsBoundary",
          "iam:PutRolePolicy",
          "iam:UpdateAssumeRolePolicy",
          "iam:UpdateRole",
          "iam:UpdateRoleDescription",
          "iam:TagRole",
          "iam:UntagRole",
        ]
        Resource  = local.protected_role_arns
        Condition = local.exempt
      },
    ],
    var.deny_iam_user_credentials ? [
      {
        Sid    = "DenyIamUserCredentials"
        Effect = "Deny"
        Action = [
          "iam:CreateUser",
          "iam:CreateAccessKey",
          "iam:CreateLoginProfile",
          "iam:UpdateLoginProfile",
        ]
        Resource  = "*"
        Condition = local.exempt
      },
    ] : [],
  )

  security_services_statements = [
    {
      Sid    = "ProtectAuditLogging"
      Effect = "Deny"
      Action = [
        "cloudtrail:DeleteTrail",
        "cloudtrail:PutEventSelectors",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateTrail",
        "config:DeleteConfigurationRecorder",
        "config:DeleteDeliveryChannel",
        "config:PutConfigurationRecorder",
        "config:StopConfigurationRecorder",
      ]
      Resource  = "*"
      Condition = local.exempt
    },
    {
      Sid    = "ProtectThreatDetection"
      Effect = "Deny"
      Action = [
        "access-analyzer:DeleteAnalyzer",
        "guardduty:CreateFilter",
        "guardduty:DeleteDetector",
        "guardduty:DisassociateFromAdministratorAccount",
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:UpdateDetector",
        "guardduty:UpdateFilter",
        "securityhub:BatchDisableStandards",
        "securityhub:DisableSecurityHub",
        "securityhub:DisassociateFromAdministratorAccount",
        "securityhub:DisassociateFromMasterAccount",
      ]
      Resource  = "*"
      Condition = local.exempt
    },
  ]

  data_and_compute_statements = [
    {
      Sid       = "ProtectEbsDefaultEncryption"
      Effect    = "Deny"
      Action    = ["ec2:DisableEbsEncryptionByDefault"]
      Resource  = "*"
      Condition = local.exempt
    },
    {
      Sid       = "ProtectAccountPublicAccessBlock"
      Effect    = "Deny"
      Action    = ["s3:PutAccountPublicAccessBlock"]
      Resource  = "*"
      Condition = local.exempt
    },
    {
      # Scoped to the instance resource: RunInstances is also authorized
      # against the AMI, subnet, volume and so on, and those requests do not
      # carry ec2:MetadataHttpTokens.
      Sid      = "RequireImdsV2OnLaunch"
      Effect   = "Deny"
      Action   = ["ec2:RunInstances"]
      Resource = "arn:${local.p}:ec2:*:*:instance/*"
      Condition = {
        StringNotEquals = { "ec2:MetadataHttpTokens" = "required" }
      }
    },
    {
      Sid       = "DenyImdsDowngrade"
      Effect    = "Deny"
      Action    = ["ec2:ModifyInstanceMetadataOptions"]
      Resource  = "*"
      Condition = local.exempt
    },
  ]

  # Global services and the handful of regional actions they depend on. They
  # are served from a single region (us-east-1 in the commercial partition),
  # so a region deny without this carve-out would break IAM, Organizations,
  # Route 53, CloudFront, Support and billing for everyone.
  global_service_actions = [
    "account:*",
    "aws-portal:*",
    "budgets:*",
    "ce:*",
    "cloudfront:*",
    "cur:*",
    "ec2:DescribeRegions",
    "globalaccelerator:*",
    "health:*",
    "iam:*",
    "organizations:*",
    "pricing:*",
    "route53:*",
    "route53domains:*",
    "s3:GetAccountPublicAccessBlock",
    "s3:ListAllMyBuckets",
    "shield:*",
    "sts:*",
    "support:*",
    "trustedadvisor:*",
    "waf:*",
    "wafv2:*",
  ]

  region_statements = [
    {
      Sid       = "DenyOutsideAllowedRegions"
      Effect    = "Deny"
      NotAction = local.global_service_actions
      Resource  = "*"
      Condition = merge(local.exempt, {
        StringNotEquals = { "aws:RequestedRegion" = var.allowed_regions }
      })
    },
  ]

  scp_statements = merge(
    {
      core              = local.core_statements
      security-services = local.security_services_statements
      data-and-compute  = local.data_and_compute_statements
    },
    var.enable_region_restriction ? { region-restriction = local.region_statements } : {},
  )

  scp_policies = var.exempt_principal_arns == null ? {} : {
    for name, statements in local.scp_statements : name => jsonencode({
      Version   = "2012-10-17"
      Statement = statements
    })
  }
}
