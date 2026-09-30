# Plan-time tests for the AI/ML SCPs. The AWS provider is mocked, so no
# credentials or organization are needed. The assertions decode the policy
# JSON that Terraform renders and check the statements themselves.

mock_provider "aws" {}

variables {
  target_ids = ["ou-abcd-11111111", "ou-abcd-22222222"]
}

run "defaults_create_three_policies" {
  command = plan

  assert {
    condition = toset(keys(aws_organizations_policy.this)) == toset([
      "deny-disable-bedrock-logging-and-guardrails",
      "lockdown-sagemaker-notebooks",
      "require-sagemaker-encryption",
    ])
    error_message = "The defaults must create the logging, notebook and encryption SCPs, and leave the model allow-list off."
  }

  assert {
    condition     = alltrue([for p in aws_organizations_policy.this : p.type == "SERVICE_CONTROL_POLICY"])
    error_message = "Every policy must be a service control policy."
  }

  assert {
    condition     = aws_organizations_policy.this["lockdown-sagemaker-notebooks"].name == "ai-ml-guardrail-lockdown-sagemaker-notebooks"
    error_message = "Policy names must use name_prefix."
  }
}

run "every_policy_attaches_to_every_target" {
  command = plan

  assert {
    condition     = length(aws_organizations_policy_attachment.this) == 6
    error_message = "3 enabled policies x 2 targets must give 6 attachments."
  }

  assert {
    condition = toset([for a in aws_organizations_policy_attachment.this : a.target_id]) == toset([
      "ou-abcd-11111111",
      "ou-abcd-22222222",
    ])
    error_message = "Attachments must cover every target and nothing else."
  }
}

run "logging_and_guardrail_deletion_are_denied" {
  command = plan

  assert {
    condition = toset(flatten([
      for s in jsondecode(aws_organizations_policy.this["deny-disable-bedrock-logging-and-guardrails"].content).Statement :
      s.Action if s.Effect == "Deny"
      ])) == toset([
      "bedrock:DeleteModelInvocationLoggingConfiguration",
      "bedrock:DeleteGuardrail",
    ])
    error_message = "The SCP must deny deleting Bedrock invocation logging and Bedrock Guardrails."
  }
}

run "notebooks_need_vpc_no_internet_no_root" {
  command = plan

  assert {
    condition = toset([
      for s in jsondecode(aws_organizations_policy.this["lockdown-sagemaker-notebooks"].content).Statement : s.Sid
      ]) == toset([
      "DenySageMakerDirectInternetAccess",
      "DenySageMakerRootAccess",
      "DenySageMakerNotebookWithoutVPC",
    ])
    error_message = "The notebook SCP must deny direct internet access, root access and notebooks outside a VPC."
  }

  assert {
    condition = one([
      for s in jsondecode(aws_organizations_policy.this["lockdown-sagemaker-notebooks"].content).Statement :
      s.Condition if s.Sid == "DenySageMakerNotebookWithoutVPC"
    ]) == { Null = { "sagemaker:VpcSubnets" = "true" } }
    error_message = "A notebook created with no VPC subnets must be denied."
  }
}

run "sagemaker_requires_kms_keys" {
  command = plan

  assert {
    condition = toset(flatten([
      for s in jsondecode(aws_organizations_policy.this["require-sagemaker-encryption"].content).Statement :
      keys(s.Condition.Null)
      ])) == toset([
      "sagemaker:VolumeKmsKey",
      "sagemaker:OutputKmsKey",
    ])
    error_message = "Notebooks and training jobs without a volume or output KMS key must be denied."
  }
}

run "model_allow_list_keeps_inference_profiles" {
  command = plan

  variables {
    enable_restrict_bedrock_foundation_models = true
    allowed_bedrock_model_patterns            = ["anthropic.claude*"]
  }

  assert {
    condition = toset(jsondecode(aws_organizations_policy.this["restrict-bedrock-foundation-models"].content).Statement[0].NotResource) == toset([
      "arn:*:bedrock:*::foundation-model/anthropic.claude*",
      "arn:*:bedrock:*:*:inference-profile/*",
      "arn:*:bedrock:*:*:application-inference-profile/*",
    ])
    error_message = "Only the allowed models and inference profiles may be exempt from the deny."
  }

  assert {
    condition     = length(aws_organizations_policy_attachment.this) == 8
    error_message = "4 enabled policies x 2 targets must give 8 attachments."
  }
}

run "disabled_policies_are_not_created" {
  command = plan

  variables {
    enable_deny_disable_bedrock_logging_and_guardrails = false
    enable_lockdown_sagemaker_notebooks                = false
    enable_require_sagemaker_encryption                = false
  }

  assert {
    condition     = length(aws_organizations_policy.this) == 0 && length(aws_organizations_policy_attachment.this) == 0
    error_message = "Turning every policy off must create no policies and no attachments."
  }
}

# The standalone JSON in policies/ai-ml-guardrails/ is for use without
# Terraform. It must not drift from what the module renders.
run "standalone_json_matches_module" {
  command = plan

  variables {
    enable_restrict_bedrock_foundation_models = true
    allowed_bedrock_model_patterns = [
      "REPLACE_WITH_ALLOWED_MODEL_PATTERN_1",
      "REPLACE_WITH_ALLOWED_MODEL_PATTERN_2",
    ]
  }

  assert {
    condition = alltrue([
      for name, p in aws_organizations_policy.this :
      jsondecode(p.content) == jsondecode(file("${path.module}/../../policies/ai-ml-guardrails/${name}.json"))
    ])
    error_message = "A file in policies/ai-ml-guardrails/ differs from the policy the module renders."
  }
}
