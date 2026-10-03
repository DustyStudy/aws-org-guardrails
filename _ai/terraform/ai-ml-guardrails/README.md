# ai-ml-guardrails (Terraform)

Deploys the SCP library in [`policies/ai-ml-guardrails/`](../../policies/ai-ml-guardrails/)
and attaches them to the Organizations targets (OUs, accounts, or the
root) you specify — protects Bedrock's audit trail, optionally restricts
which foundation models can be invoked, and locks down SageMaker notebook
instances (no direct internet access, no root access, VPC + KMS
required). An opt-in SCP denies Bedrock discovery and invocation to IAM
users, so leaked long-term keys can't be used for LLMjacking.

Full policy descriptions and variables live in
[`policies/ai-ml-guardrails/README.md`](../../policies/ai-ml-guardrails/README.md#using-terraform) —
this directory just holds the module (`main.tf`, `variables.tf`,
`outputs.tf`, `versions.tf`).

Quick start:

```hcl
module "ai_ml_guardrails" {
  source = "github.com/DustyStudy/aws-ai-guardrails//terraform/ai-ml-guardrails"

  target_ids                                = ["ou-abcd-11111111", "123456789012"]
  enable_restrict_bedrock_foundation_models = true
  allowed_bedrock_model_patterns            = ["anthropic.claude*", "amazon.titan*"]
}
```

`enable_deny_bedrock_long_term_credentials` is also off by default. Before
turning it on, check CloudTrail for Bedrock calls whose
`userIdentity.type` is `IAMUser`; any such caller is denied once it's on,
unless listed in `bedrock_iam_user_exempt_principal_arns`.

`enable_restrict_bedrock_foundation_models` is off by default — turn it
on only after populating `allowed_bedrock_model_patterns`, or you'll
block all Bedrock usage in the account.
