# sagemaker-notebook-exposure / config-rule (Terraform)

Continuous-compliance path: an AWS Config managed rule
(`SAGEMAKER_NOTEBOOK_NO_DIRECT_INTERNET_ACCESS`) evaluates every SageMaker
notebook instance on a schedule, flagging any with direct internet access
enabled. An SSM Automation document invokes the same remediation Lambda
used by `../event-driven/` to stop and reconfigure it — catching
notebooks that existed before this module was applied, or that drifted
outside the event-driven path's coverage.

## Important limitation

There is **no AWS Config managed rule for notebook root access** as of
this writing — only direct internet access has one. That means:

- This path catches **pre-existing or drifted direct-internet-access**
  notebooks.
- It does **not** catch pre-existing root-access-enabled notebooks that
  were never touched by a create/update event since `../event-driven/`
  was applied.

Apply both modules for the best coverage, and consider a one-time manual
audit (`aws sagemaker list-notebook-instances` + `describe-notebook-instance`
per instance) to catch any pre-existing root-access notebooks this
doesn't reach.

## Prerequisites

**AWS Config must already be enabled** in the account/region.

## Usage

```hcl
module "sagemaker_notebook_exposure_config_rule" {
  source = "github.com/DustyStudy/aws-ai-guardrails//terraform/sagemaker-notebook-exposure/config-rule"

  notification_email          = "you@example.com"
  maximum_execution_frequency = "TwentyFour_Hours"
}
```

Requires the `hashicorp/archive` provider in addition to `hashicorp/aws`.
Works the same in GovCloud.

## Inputs

| Name | Description | Default |
|---|---|---|
| `name_prefix` | Prefix for all resource names | `sagemaker-notebook-config` |
| `notification_email` | Email to subscribe to the SNS topic (optional) | `""` |
| `auto_restart` | Restart the notebook after remediation | `false` |
| `maximum_execution_frequency` | How often Config re-evaluates all notebooks | `TwentyFour_Hours` |
| `code_signing_config_arn` | ARN of an existing code-signing config (optional) | `null` |

## Outputs

| Name | Description |
|---|---|
| `lambda_function_arn` | ARN of the remediation Lambda |
| `sns_topic_arn` | ARN of the SNS notification topic |
| `config_rule_name` | Name of the AWS Config rule |

## Notes

- This module applies its **own** copy of the remediation Lambda
  (separate from `../event-driven/`'s) — the two modules are fully
  independent, matching the pattern used elsewhere in this repo.
- It also includes its own notebook state-change EventBridge rule so
  notebooks it flags and stops still get their settings fixed once
  actually stopped — the SSM Automation invocation only performs the
  "flag and stop" half.
- Auto-remediation retries up to 3 times, 60 seconds apart, before
  leaving the resource flagged non-compliant for manual review.
