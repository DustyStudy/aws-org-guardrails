locals {
  deny_disable_bedrock_logging_and_guardrails_content = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid      = "DenyDisableBedrockInvocationLogging"
          Effect   = "Deny"
          Action   = "bedrock:DeleteModelInvocationLoggingConfiguration"
          Resource = "*"
        },
        {
          Sid      = "DenyDeleteBedrockGuardrails"
          Effect   = "Deny"
          Action   = "bedrock:DeleteGuardrail"
          Resource = "*"
        },
      ],
      # Put can turn logging off as surely as Delete: point it at another
      # bucket or drop text delivery. Only the listed roles (the enforcement
      # Lambda, the pipeline that sets logging up) may still call it.
      length(var.bedrock_logging_admin_role_arns) == 0 ? [] : [{
        Sid       = "DenyReconfigureBedrockInvocationLogging"
        Effect    = "Deny"
        Action    = "bedrock:PutModelInvocationLoggingConfiguration"
        Resource  = "*"
        Condition = { ArnNotLike = { "aws:PrincipalArn" = var.bedrock_logging_admin_role_arns } }
      }]
    )
  })

  restrict_bedrock_foundation_models_content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DenyDisallowedFoundationModels"
      Effect = "Deny"
      Action = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
      # Inference profiles (e.g. us.anthropic.*) are separate resource ARNs
      # that Bedrock authorizes alongside the underlying foundation-model
      # ARN, so they're allowed here and the model allow-list still applies.
      NotResource = concat(
        [
          for pattern in var.allowed_bedrock_model_patterns :
          "arn:*:bedrock:*::foundation-model/${pattern}"
        ],
        [
          "arn:*:bedrock:*:*:inference-profile/*",
          "arn:*:bedrock:*:*:application-inference-profile/*",
        ]
      )
    }]
  })

  # Stolen long-term keys are validated and monetized through Bedrock within
  # minutes: GetCallerIdentity, then ListFoundationModels and a burst of
  # InvokeModel calls across Regions (Datadog Security Labs, 2026-09-18).
  # Humans should reach Bedrock through Identity Center and workloads
  # through roles, so an IAM user (access key, console password or Bedrock
  # API key, which is also bound to an IAM user) has no business here.
  # aws:PrincipalType is "User" only for IAM users, never for roles or
  # federated sessions.
  deny_bedrock_long_term_credentials_content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DenyBedrockToIamUsers"
      Effect = "Deny"
      # Prefix wildcards are deliberate: InvokeModel* also covers
      # InvokeModelWithResponseStream and the bidirectional stream (Converse
      # and ConverseStream authorize as InvokeModel*), and ListFoundationModel*
      # covers the agreement-offer listing used to enable a model.
      Action = [
        "bedrock:InvokeModel*",
        "bedrock:CreateModelInvocationJob",
        "bedrock:InvokeAgent",
        "bedrock:CallWithBearerToken",
        "bedrock:ListFoundationModel*",
        "bedrock:GetFoundationModelAvailability",
        "bedrock:PutFoundationModelEntitlement",
      ]
      Resource = "*"
      Condition = merge(
        { StringEquals = { "aws:PrincipalType" = "User" } },
        length(var.bedrock_iam_user_exempt_principal_arns) > 0 ? {
          ArnNotLike = { "aws:PrincipalArn" = var.bedrock_iam_user_exempt_principal_arns }
        } : {}
      )
    }]
  })

  lockdown_sagemaker_notebooks_content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenySageMakerDirectInternetAccess"
        Effect    = "Deny"
        Action    = ["sagemaker:CreateNotebookInstance", "sagemaker:UpdateNotebookInstance"]
        Resource  = "*"
        Condition = { StringEquals = { "sagemaker:DirectInternetAccess" = "Enabled" } }
      },
      {
        Sid       = "DenySageMakerRootAccess"
        Effect    = "Deny"
        Action    = ["sagemaker:CreateNotebookInstance", "sagemaker:UpdateNotebookInstance"]
        Resource  = "*"
        Condition = { StringEquals = { "sagemaker:RootAccess" = "Enabled" } }
      },
      {
        Sid       = "DenySageMakerNotebookWithoutVPC"
        Effect    = "Deny"
        Action    = "sagemaker:CreateNotebookInstance"
        Resource  = "*"
        Condition = { Null = { "sagemaker:VpcSubnets" = "true" } }
      },
    ]
  })

  require_sagemaker_encryption_content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenySageMakerNotebookWithoutKMS"
        Effect    = "Deny"
        Action    = "sagemaker:CreateNotebookInstance"
        Resource  = "*"
        Condition = { Null = { "sagemaker:VolumeKmsKey" = "true" } }
      },
      {
        Sid       = "DenySageMakerTrainingJobWithoutVolumeKMS"
        Effect    = "Deny"
        Action    = "sagemaker:CreateTrainingJob"
        Resource  = "*"
        Condition = { Null = { "sagemaker:VolumeKmsKey" = "true" } }
      },
      {
        Sid       = "DenySageMakerTrainingJobWithoutOutputKMS"
        Effect    = "Deny"
        Action    = "sagemaker:CreateTrainingJob"
        Resource  = "*"
        Condition = { Null = { "sagemaker:OutputKmsKey" = "true" } }
      },
    ]
  })

  # SageMaker Python SDK default_bucket() builds a predictable name,
  # sagemaker-<region>-<account-id>, and before 2.257.3 / 3.10.0 never checked
  # who owns it. Someone who creates that bucket first in their own account
  # receives uploaded training code and can swap it, so the job runs their
  # code with the execution role (AWS bulletin 2026-142-AWS, CVE-2026-112408).
  # The ARN pattern matches only that shape (a Region ending in -<digit>,
  # then a 12-digit account ID), so AWS-owned sample buckets such as
  # sagemaker-sample-files are left alone. A bucket owned outside the
  # organization has a different or no aws:ResourceOrgID, so it is denied.
  deny_sagemaker_default_bucket_outside_org_content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DenySageMakerDefaultBucketOutsideOrg"
      Effect = "Deny"
      Action = [
        "s3:GetObject*",
        "s3:PutObject*",
        "s3:ListBucket",
        "s3:GetBucketLocation",
      ]
      Resource = [
        "arn:*:s3:::sagemaker-*-?-????????????",
        "arn:*:s3:::sagemaker-*-?-????????????/*",
      ]
      Condition = {
        StringNotEquals = { "aws:ResourceOrgID" = "$${aws:PrincipalOrgID}" }
      }
    }]
  })

  policies = {
    deny-disable-bedrock-logging-and-guardrails = {
      enabled     = var.enable_deny_disable_bedrock_logging_and_guardrails
      description = "Denies disabling Bedrock model invocation logging or deleting Bedrock Guardrails."
      content     = local.deny_disable_bedrock_logging_and_guardrails_content
    }
    restrict-bedrock-foundation-models = {
      enabled     = var.enable_restrict_bedrock_foundation_models
      description = "Restricts Bedrock model invocation to an allow-listed set of foundation models."
      content     = local.restrict_bedrock_foundation_models_content
    }
    deny-bedrock-long-term-credentials = {
      enabled     = var.enable_deny_bedrock_long_term_credentials
      description = "Denies Bedrock model discovery, access and invocation to IAM users (long-term keys and Bedrock API keys)."
      content     = local.deny_bedrock_long_term_credentials_content
    }
    deny-sagemaker-default-bucket-outside-org = {
      enabled     = var.enable_deny_sagemaker_default_bucket_outside_org
      description = "Denies S3 access to SageMaker default-bucket names (sagemaker-<region>-<account>) owned outside the organization."
      content     = local.deny_sagemaker_default_bucket_outside_org_content
    }
    lockdown-sagemaker-notebooks = {
      enabled     = var.enable_lockdown_sagemaker_notebooks
      description = "Denies SageMaker notebook instances with direct internet access, root access, or no VPC."
      content     = local.lockdown_sagemaker_notebooks_content
    }
    require-sagemaker-encryption = {
      enabled     = var.enable_require_sagemaker_encryption
      description = "Denies SageMaker notebook instances and training jobs that don't specify a KMS key."
      content     = local.require_sagemaker_encryption_content
    }
  }

  enabled_policies = { for name, p in local.policies : name => p if p.enabled }

  attachments = {
    for pair in setproduct(keys(local.enabled_policies), var.target_ids) :
    "${pair[0]}|${pair[1]}" => { policy_name = pair[0], target_id = pair[1] }
  }
}

resource "aws_organizations_policy" "this" {
  for_each = local.enabled_policies

  name        = "${var.name_prefix}-${each.key}"
  description = each.value.description
  type        = "SERVICE_CONTROL_POLICY"
  content     = each.value.content
}

resource "aws_organizations_policy_attachment" "this" {
  for_each = local.attachments

  policy_id = aws_organizations_policy.this[each.value.policy_name].id
  target_id = each.value.target_id
}
