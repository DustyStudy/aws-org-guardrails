# ai-ml-guardrails

A library of preventive Service Control Policies for AI/ML workloads on
AWS: protecting Bedrock's audit trail, optionally restricting which
foundation models can be invoked, and locking down SageMaker notebook
instances. Same structure as [`scp-guardrails`](../scp-guardrails/) —
standalone JSON, or deploy/attach via Terraform.

## Policies included

| File | What it denies |
|---|---|
| `deny-disable-bedrock-logging-and-guardrails.json` | Disabling Bedrock model invocation logging, or deleting a Bedrock Guardrail |
| `restrict-bedrock-foundation-models.json` | Invoking any Bedrock foundation model not on your allow-list |
| `lockdown-sagemaker-notebooks.json` | SageMaker notebooks with direct internet access, root access enabled, or no VPC |
| `require-sagemaker-encryption.json` | SageMaker notebooks and training jobs that don't specify a KMS key |

## Why these specifically

- **Bedrock invocation logging** is your only audit trail of what prompts
  and completions actually went through your models — without it, an
  incident involving a leaked prompt or a jailbroken agent is nearly
  unreconstructable after the fact. This SCP denies deleting the logging
  configuration; it can't stop someone *reconfiguring* it (e.g. pointing it
  at another bucket or disabling text delivery), since that is the same
  `PutModelInvocationLoggingConfiguration` call the enforcement Lambda
  itself needs. Pair it with
  [`bedrock-logging-enforcement`](../../terraform/bedrock-logging-enforcement/)
  to detect and revert that.
- **Bedrock Guardrails** (content filtering, PII redaction, topic
  restrictions) are easy to configure and easy to quietly delete later.
  This denies the delete.
- **A foundation-model allow-list** matters for cost control and data
  governance — without one, anyone with `bedrock:InvokeModel` can call
  *any* model available in the account/region, including ones your org
  hasn't reviewed for data-handling terms. **This one is off by default** —
  turn it on only after populating `AllowedBedrockModelPatterns`/
  `allowed_bedrock_model_patterns` with the models you've actually
  approved, or you'll block all Bedrock usage in the account.
- **SageMaker notebook lockdown** closes the single most common SageMaker
  misconfiguration: a notebook instance with `DirectInternetAccess`
  enabled sitting outside a VPC, reachable from the internet, often with
  root access too — effectively an unmanaged EC2 instance with AWS
  credentials attached.

## Using the raw JSON directly

```bash
aws organizations create-policy \
  --name lockdown-sagemaker-notebooks \
  --type SERVICE_CONTROL_POLICY \
  --content file://policies/ai-ml-guardrails/lockdown-sagemaker-notebooks.json

aws organizations attach-policy \
  --policy-id p-xxxxxxxx \
  --target-id ou-xxxx-xxxxxxxx
```

## Using Terraform

```hcl
module "ai_ml_guardrails" {
  source = "github.com/DustyStudy/aws-cloud-security-toolbox//terraform/ai-ml-guardrails"

  target_ids                                = ["ou-abcd-11111111", "123456789012"]
  enable_restrict_bedrock_foundation_models = true
  allowed_bedrock_model_patterns            = ["anthropic.claude*", "amazon.titan*"]
}
```

## Notes

- The allow-list is enforced against `foundation-model` ARNs. Calls made
  through a cross-region or application inference profile (e.g.
  `us.anthropic.*`) are also authorized against the underlying model ARN,
  so inference-profile ARNs are permitted and the model allow-list still
  applies. Custom and provisioned models are *not* exempted; add their
  ARNs to the `NotResource` list if you use them.
- Bedrock foundation models are versioned and updated by AWS regularly -
  review `AllowedBedrockModelPatterns` periodically so a new model your
  teams need isn't silently blocked.
- These SCPs only govern the AWS-API surface (creating/invoking
  resources). They say nothing about what an agent *does* once it has
  valid credentials and a broad IAM role — see
  [`ai-agent-iam-auditor`](../ai-agent-iam-auditor/) for detecting
  over-permissioned agent roles, which is the complementary risk.
- As with all SCPs, test in a non-production OU first — especially the
  model allow-list, which is an all-or-nothing gate once enabled.
