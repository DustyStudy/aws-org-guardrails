# Service control policies, grouped into bundles.
#
# AWS allowed at most 5 SCPs attached directly to a root, OU or account, of
# 5,120 characters each, until it doubled both in May 2026. The bundles keep
# to the old limits on purpose, as a compatibility margin and to leave room
# for an organization's own SCPs: four bundles leave a slot for FullAWSAccess,
# and tests/test_scps.py checks both limits on every render.
#
# Every statement is a Deny. Allow comes from FullAWSAccess (or whatever
# allow-list SCPs the organization already uses), so these bundles only
# remove permissions and never grant any.

locals {
  p = var.partition

  # The threat behind each opt-in statement, with sources, is in
  # CHANGELOG.md; comments here keep only why each condition is shaped as it is.
  #
  # Most statements carry this condition so the break-glass and security
  # pipeline roles can still repair what the guardrail protects.
  exempt = {
    ArnNotLike = { "aws:PrincipalArn" = var.exempt_principal_arns }
  }

  # Roles that may still turn instance termination and stop protection on
  # or off when deny_instance_protection_changes is set.
  instance_protection_exempt = concat(coalesce(var.exempt_principal_arns, []), var.instance_protection_exempt_principal_arns)

  # Opt-in (deny_instance_protection_changes). A for-filter instead of a
  # conditional: the three statements differ in shape, so they can't be
  # unified with an empty list.
  instance_protection_statements = [
    {
      # Attackers mining with stolen IAM credentials turned on termination
      # protection so responders had to switch it off before deleting the
      # instances. Stop protection blocks the isolation
      # playbook's StopInstances the same way. These three deny changing
      # either after launch, on or off, except to exempt roles.
      # EC2 sets both ec2:Attribute/<Name> and ec2:Attribute for either
      # request form (DisableApiTermination.Value or Attribute=<name>);
      # confirmed live 2026-11-12, docs/PROOF.md run 3.
      # Not covered: protection set at launch (RunInstances or a launch
      # template), which has no condition key.
      Sid      = "DenyInstanceDisableApiTerminationChange"
      Effect   = "Deny"
      Action   = ["ec2:ModifyInstanceAttribute"]
      Resource = "arn:${local.p}:ec2:*:*:instance/*"
      Condition = {
        ArnNotLike = { "aws:PrincipalArn" = local.instance_protection_exempt }
        Null       = { "ec2:Attribute/DisableApiTermination" = "false" }
      }
    },
    {
      Sid      = "DenyInstanceDisableApiStopChange"
      Effect   = "Deny"
      Action   = ["ec2:ModifyInstanceAttribute"]
      Resource = "arn:${local.p}:ec2:*:*:instance/*"
      Condition = {
        ArnNotLike = { "aws:PrincipalArn" = local.instance_protection_exempt }
        Null       = { "ec2:Attribute/DisableApiStop" = "false" }
      }
    },
    {
      Sid      = "DenyInstanceProtectionAttributeChange"
      Effect   = "Deny"
      Action   = ["ec2:ModifyInstanceAttribute"]
      Resource = "arn:${local.p}:ec2:*:*:instance/*"
      Condition = {
        ArnNotLike             = { "aws:PrincipalArn" = local.instance_protection_exempt }
        StringEqualsIgnoreCase = { "ec2:Attribute" = ["disableApiTermination", "disableApiStop"] }
      }
    },
  ]

  protected_role_arns = [
    for prefix in var.protected_role_name_prefixes : "arn:${local.p}:iam::*:role/${prefix}*"
  ]
  # Policy names can sit under any path; the second pattern matches a name
  # with the prefix in the last path segment, such as policy/team/security-x.
  protected_policy_arns = flatten([
    for prefix in var.protected_role_name_prefixes : [
      "arn:${local.p}:iam::*:policy/${prefix}*",
      "arn:${local.p}:iam::*:policy/*/${prefix}*",
    ]
  ])

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
        # centralized root access instead. Those sessions (sts:AssumeRoot)
        # also carry the root ARN, so aws:AssumedRoot must be absent for the
        # deny to apply; AssumeRoot is itself limited to a few task policies.
        Sid      = "DenyRootUser"
        Effect   = "Deny"
        Action   = ["*"]
        Resource = "*"
        Condition = {
          ArnLike = { "aws:PrincipalArn" = "arn:${local.p}:iam::*:root" }
          Null    = { "aws:AssumedRoot" = "true" }
        }
      },
      {
        # CreateRole is included so nobody can create a role whose name
        # matches an exempt principal and inherit its exemption. The
        # policies module requires every exempt role to be covered by a
        # protected prefix for the same reason. PassRole is included because
        # compute that runs as an exempt role inherits its exemption.
        Sid    = "DenyProtectedRoleChanges"
        Effect = "Deny"
        Action = [
          "iam:AttachRolePolicy",
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:DeleteRolePermissionsBoundary",
          "iam:DeleteRolePolicy",
          "iam:DetachRolePolicy",
          "iam:PassRole",
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
      {
        # A customer managed policy attached to a protected role changes
        # that role when its default version changes. Name such policies
        # with a protected prefix so this statement covers them.
        Sid    = "DenyProtectedPolicyChanges"
        Effect = "Deny"
        Action = [
          "iam:CreatePolicy",
          "iam:CreatePolicyVersion",
          "iam:DeletePolicy",
          "iam:DeletePolicyVersion",
          "iam:SetDefaultPolicyVersion",
        ]
        Resource  = local.protected_policy_arns
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
    var.deny_service_specific_credentials ? [
      {
        # A Bedrock API key, CodeCommit Git password or Keyspaces password is
        # a long-term secret bound to an existing IAM user, and minting one
        # needs no access key. LLMjacking actors add a Bedrock API key to the
        # identity they control as a second way in. DenyIamUserCredentials stops new users
        # and access keys, not these. Reset issues a new secret for an
        # existing credential, so it is denied too. Update only switches a
        # credential between Active and Inactive and stays open, so anyone
        # can still deactivate one.
        Sid    = "DenyServiceSpecificCredentials"
        Effect = "Deny"
        Action = [
          "iam:CreateServiceSpecificCredential",
          "iam:ResetServiceSpecificCredential",
        ]
        Resource  = "*"
        Condition = local.exempt
      },
    ] : [],
    var.deny_ses_to_iam_users ? [
      {
        # Access keys scraped from web hosts are checked for SES first: the
        # key's secret converts offline into an SES SMTP password, and a
        # verified sender in a production-access account is worth more than
        # the key itself. The
        # SMTP endpoint authorizes as ses:SendRawEmail, so it is covered.
        # ses:* is deliberate: quota checks, identity verification and the
        # production-access request are all part of the same abuse, and an
        # IAM user that is not a listed SMTP sender has no use for any of it.
        # aws:PrincipalType is "User" only for IAM users, so roles and
        # Identity Center sessions keep SES. The role exemption would never
        # match a user, so this statement has its own user list instead.
        Sid      = "DenySesToIamUsers"
        Effect   = "Deny"
        Action   = ["ses:*"]
        Resource = "*"
        Condition = merge(
          { StringEquals = { "aws:PrincipalType" = "User" } },
          length(var.ses_iam_user_exempt_principal_arns) > 0 ? {
            ArnNotLike = { "aws:PrincipalArn" = var.ses_iam_user_exempt_principal_arns }
          } : {}
        )
      },
    ] : [],
    [
      # A credential handed to an outside vendor is only as safe as that
      # vendor: a breach there exposes every customer credential it holds.
      # This denies a vendor's roles and users
      # access unless the call comes from the source ranges that vendor
      # publishes, so a copied credential fails from the attacker's network.
      # aws:SourceIp is absent on VPC endpoint calls, so NotIpAddress denies
      # those too. AWS redacts network context on calls services make for
      # the caller, so those are skipped. Limits: sts:GetCallerIdentity
      # cannot be denied; sessions minted on the vendor network before the
      # theft (a chained role, a GetFederationToken user) carry another ARN,
      # so list those roles too; code run on the vendor's own machines
      # passes.
      for name, vendor in var.third_party_vendor_networks : {
        Sid      = "DenyVendorOffNetwork${name}"
        Effect   = "Deny"
        Action   = ["*"]
        Resource = "*"
        Condition = merge(local.exempt, {
          ArnLike      = { "aws:PrincipalArn" = vendor.principal_arns }
          NotIpAddress = { "aws:SourceIp" = vendor.source_cidrs }
          BoolIfExists = { "aws:ViaAWSService" = "false", "aws:PrincipalIsAWSService" = "false" }
        })
      }
    ],
  )

  security_services_statements = [
    {
      Sid    = "ProtectAuditLogging"
      Effect = "Deny"
      Action = [
        "cloudtrail:DeleteEventDataStore",
        "cloudtrail:DeleteTrail",
        "cloudtrail:PutEventSelectors",
        "cloudtrail:PutInsightSelectors",
        "cloudtrail:StopEventDataStoreIngestion",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateEventDataStore",
        "cloudtrail:UpdateTrail",
        "config:DeleteConfigurationAggregator",
        "config:DeleteConfigurationRecorder",
        "config:DeleteDeliveryChannel",
        "config:PutConfigurationAggregator",
        "config:PutConfigurationRecorder",
        "config:PutDeliveryChannel",
        "config:StopConfigurationRecorder",
      ]
      Resource  = "*"
      Condition = local.exempt
    },
    {
      # Blinding a detector works as well as disabling it: trusted IP and
      # entity lists, archive and automation rules suppress findings, and
      # single controls can be turned off inside an enabled standard.
      Sid    = "ProtectThreatDetection"
      Effect = "Deny"
      Action = [
        "access-analyzer:ApplyArchiveRule",
        "access-analyzer:CreateArchiveRule",
        "access-analyzer:DeleteAnalyzer",
        "access-analyzer:UpdateArchiveRule",
        "guardduty:CreateFilter",
        "guardduty:CreateIPSet",
        "guardduty:CreateTrustedEntitySet",
        "guardduty:DeleteDetector",
        "guardduty:DeleteMembers",
        "guardduty:DeletePublishingDestination",
        "guardduty:DisassociateFromAdministratorAccount",
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:DisassociateMembers",
        "guardduty:StopMonitoringMembers",
        "guardduty:UpdateDetector",
        "guardduty:UpdateFilter",
        "guardduty:UpdateIPSet",
        "guardduty:UpdateTrustedEntitySet",
        "securityhub:BatchDisableStandards",
        "securityhub:BatchUpdateAutomationRules",
        "securityhub:BatchUpdateStandardsControlAssociations",
        "securityhub:CreateAutomationRule",
        "securityhub:CreateAutomationRuleV2",
        "securityhub:DeleteMembers",
        "securityhub:DisableSecurityHub",
        "securityhub:DisableSecurityHubV2",
        "securityhub:DisassociateFromAdministratorAccount",
        "securityhub:DisassociateFromMasterAccount",
        "securityhub:DisassociateMembers",
        "securityhub:UpdateAutomationRuleV2",
        "securityhub:UpdateStandardsControl",
      ]
      Resource  = "*"
      Condition = local.exempt
    },
  ]

  data_and_compute_statements = concat([
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
      # Lets a change through only when it requests HttpTokens=required, so
      # teams can still move old instances to IMDSv2. ec2:Attribute/<name>
      # carries the requested value (ec2:MetadataHttpTokens describes the
      # instance). A request without HttpTokens lacks the key and is denied,
      # so callers pass HttpTokens=required with every change.
      Sid      = "DenyImdsDowngrade"
      Effect   = "Deny"
      Action   = ["ec2:ModifyInstanceMetadataOptions"]
      Resource = "*"
      Condition = merge(local.exempt, {
        StringNotEquals = { "ec2:Attribute/HttpTokens" = "required" }
      })
    },
    {
      # RAM shares stay inside the organization. Sharing with the
      # organization or its OUs sets allowExternalPrincipals to false.
      Sid       = "DenyExternalResourceShares"
      Effect    = "Deny"
      Action    = ["ram:CreateResourceShare", "ram:UpdateResourceShare"]
      Resource  = "*"
      Condition = merge(local.exempt, { Bool = { "ram:RequestedAllowsExternalPrincipals" = "true" } })
    },
    {
      # Covers shares that already allowed external principals before this
      # guardrail was attached: nothing new can be added to them.
      Sid       = "DenyAssociateToExternalShares"
      Effect    = "Deny"
      Action    = ["ram:AssociateResourceShare"]
      Resource  = "*"
      Condition = merge(local.exempt, { Bool = { "ram:AllowsExternalPrincipals" = "true" } })
    },
    ], var.require_imds_hop_limit_one ? [
    {
      # A container on an instance reaches the instance role's credentials
      # through IMDS only when the hop limit is 2 or more, which a backdoored
      # container image can use. A hop limit of 1 keeps bridge-networked
      # containers out; host-networked containers and processes on the host
      # still reach IMDS. NumericNotEquals is true when the key is missing,
      # so callers must set the hop limit, as with RequireImdsV2OnLaunch.
      # RequireImdsHopLimitOneOnModify stops raising it after launch. Launches by
      # service-linked roles (Auto Scaling, EKS managed node groups) are
      # outside SCPs, so this neither breaks nor covers them.
      Sid      = "RequireImdsHopLimitOne"
      Effect   = "Deny"
      Action   = ["ec2:RunInstances"]
      Resource = "arn:${local.p}:ec2:*:*:instance/*"
      Condition = merge(local.exempt, {
        NumericNotEquals = { "ec2:MetadataHttpPutResponseHopLimit" = "1" }
      })
    },
    {
      # DenyImdsDowngrade allows metadata changes that keep IMDSv2, which
      # could raise the hop limit. With this opt-in every change must also
      # pass HttpPutResponseHopLimit=1.
      Sid      = "RequireImdsHopLimitOneOnModify"
      Effect   = "Deny"
      Action   = ["ec2:ModifyInstanceMetadataOptions"]
      Resource = "*"
      Condition = merge(local.exempt, {
        NumericNotEquals = { "ec2:Attribute/HttpPutResponseHopLimit" = "1" }
      })
    },
    ] : [], var.deny_athena_results_bucket_outside_org ? [
    {
      # AWS SDK for pandas (awswrangler) before 3.16.1 used
      # aws-athena-query-results-<account-id>-<region> as the default Athena
      # result location without checking who owns it. Whoever creates that
      # name first in their own account reads the query results and can
      # change what the caller gets back (CVE-2026-118029). Athena reads and
      # writes results with the caller's
      # credentials, so the deny applies. aws:ResourceOrgID is missing for a
      # bucket in a standalone account, and StringNotEquals is true when the
      # key is missing, so those are denied too. No exemption: no role has a
      # reason to use a look-alike bucket in another organization.
      Sid    = "DenyAthenaResultsBucketOutsideOrg"
      Effect = "Deny"
      Action = ["s3:GetObject*", "s3:PutObject*", "s3:ListBucket", "s3:GetBucketLocation"]
      Resource = [
        "arn:${local.p}:s3:::aws-athena-query-results-????????????-*",
        "arn:${local.p}:s3:::aws-athena-query-results-????????????-*/*",
      ]
      Condition = {
        StringNotEquals = { "aws:ResourceOrgID" = "$${aws:PrincipalOrgID}" }
      }
    },
    ] : [], [for statement in local.instance_protection_statements : statement if var.deny_instance_protection_changes], var.deny_tagged_kms_keys_off_org_network ? [
    {
      # Credentials lifted from a laptop work from anywhere unless the key
      # also checks the network. This denies using or re-pointing a KMS key
      # tagged guardrails:network-perimeter=true unless the call arrives
      # through a VPC endpoint owned by an account in the caller's
      # organization. aws:VpceOrgID is absent on public endpoints, so
      # ...IfExists denies those. CreateGrant and PutKeyPolicy are in scope
      # because a grant or key-policy entry for an outside account is not
      # bound by this SCP. ReplicateKey is in scope because a replica does
      # not inherit the primary's tags. Tag and untag are in scope so the tag cannot be
      # removed from off the network first. Calls AWS services make for the
      # caller (S3 SSE-KMS, EBS) drop the VPC endpoint context, so
      # aws:ViaAWSService and aws:PrincipalIsAWSService skip them; data read
      # through such a service (an SSE-KMS object) needs that service's own
      # perimeter.
      Sid    = "DenyTaggedKmsKeysOffOrgNetwork"
      Effect = "Deny"
      Action = [
        "kms:CreateGrant",
        "kms:Decrypt",
        "kms:DeriveSharedSecret",
        "kms:GenerateDataKey*",
        "kms:GenerateMac",
        "kms:PutKeyPolicy",
        "kms:ReEncrypt*",
        "kms:ReplicateKey",
        "kms:Sign",
        "kms:TagResource",
        "kms:UntagResource",
      ]
      Resource = "arn:${local.p}:kms:*:*:key/*"
      Condition = merge(local.exempt, {
        StringEquals            = { "aws:ResourceTag/guardrails:network-perimeter" = "true" }
        StringNotEqualsIfExists = { "aws:VpceOrgID" = "$${aws:PrincipalOrgID}" }
        BoolIfExists            = { "aws:ViaAWSService" = "false", "aws:PrincipalIsAWSService" = "false" }
      })
    },
  ] : [])

  # Global services and the handful of regional actions they depend on. They
  # are served from a single region (us-east-1 in the commercial partition),
  # so a region deny without this carve-out would break IAM, Organizations,
  # Route 53, CloudFront, Support and billing for everyone.
  # acm is regional, but CloudFront only takes certificates from us-east-1,
  # so it is carved out as in AWS's own example. billing, payments, tax,
  # invoicing and freetier replaced aws-portal; User Notifications'
  # control plane (notifications, notifications-contacts) and ecr-public
  # are served from us-east-1 only.
  global_service_actions = [
    "account:*",
    "acm:*",
    "aws-portal:*",
    "billing:*",
    "budgets:*",
    "ce:*",
    "cloudfront:*",
    "cur:*",
    "ec2:DescribeRegions",
    "ecr-public:*",
    "freetier:*",
    "globalaccelerator:*",
    "health:*",
    "iam:*",
    "invoicing:*",
    "notifications:*",
    "notifications-contacts:*",
    "organizations:*",
    "payments:*",
    "pricing:*",
    "route53:*",
    "route53domains:*",
    "s3:GetAccountPublicAccessBlock",
    "s3:ListAllMyBuckets",
    "shield:*",
    "sts:*",
    "support:*",
    "tax:*",
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
