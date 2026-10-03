# bedrock-logging-enforcement (Terraform)

Checks the account's Bedrock **model invocation logging** configuration on
a schedule and re-enables it if it's missing or was disabled, notifying
via SNS.

## How it works

1. A scheduled EventBridge rule (default: daily, via `schedule_expression`)
   invokes the Lambda.
2. The Lambda calls `bedrock:GetModelInvocationLoggingConfiguration` and
   compares it against the desired configuration (S3 bucket + CloudWatch
   Logs group, both created by this module).
3. If logging is disabled or drifted, the Lambda calls
   `bedrock:PutModelInvocationLoggingConfiguration` to restore it and
   publishes a summary to SNS.

## Usage

```hcl
module "bedrock_logging_enforcement" {
  source = "github.com/DustyStudy/aws-ai-guardrails//terraform/bedrock-logging-enforcement"

  notification_email = "you@example.com"
}
```

Requires the `hashicorp/archive` provider in addition to `hashicorp/aws`.
Works the same in GovCloud — check Bedrock's availability in your target
GovCloud region first.

## Inputs

| Name | Description | Default |
|---|---|---|
| `name_prefix` | Prefix for all resource names | `bedrock-logging-enforcement` |
| `notification_email` | Email to subscribe to the SNS topic (optional) | `""` |
| `schedule_expression` | EventBridge schedule | `rate(1 day)` |
| `log_text_data` | Log text prompts/completions | `true` |
| `log_image_data` | Log image inputs/outputs (can be large) | `false` |
| `log_embedding_data` | Log embedding inputs | `false` |
| `code_signing_config_arn` | ARN of an existing code-signing config (optional) | `null` |

## Outputs

| Name | Description |
|---|---|
| `lambda_function_arn` | ARN of the enforcement Lambda |
| `sns_topic_arn` | ARN of the SNS notification topic |
| `bedrock_log_bucket_name` | S3 bucket Bedrock delivers logs to |
| `bedrock_log_group_name` | CloudWatch Logs group Bedrock delivers logs to |

## Notes

- The S3 destination bucket uses SSE-S3, not SSE-KMS — a documented AWS
  limitation of Bedrock's S3 log-delivery mechanism.
- Only account-level logging is covered — extend the Lambda if you use
  application inference profiles with their own logging needs.
- Pair this with [`ai-ml-guardrails`](../ai-ml-guardrails/)'s
  `deny-disable-bedrock-logging-and-guardrails` SCP: the SCP prevents the
  config from being deleted outright, this catches drift and restores it
  if it happens anyway.
