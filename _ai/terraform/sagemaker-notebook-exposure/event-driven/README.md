# sagemaker-notebook-exposure / event-driven (Terraform)

Detects SageMaker notebook instances created or updated with **direct
internet access** or **root access** enabled, and remediates them
automatically.

## Why this is two EventBridge rules, not one

SageMaker only allows changing `DirectInternetAccess` or `RootAccess`
while a notebook instance is **stopped**. Stopping a running instance
takes a couple of minutes — too long to block inside one Lambda
invocation — so this is a two-phase flow, both handled by the same
Lambda:

1. **`notebook_create_or_update`** rule — matches
   `CreateNotebookInstance`/`UpdateNotebookInstance` CloudTrail events. If
   the notebook is non-compliant, the Lambda tags it
   `sagemaker-remediation-pending=true` and stops it if running.
2. **`notebook_state_change`** rule — matches SageMaker's own **native**
   "Notebook Instance State Change" event. When a notebook reaches
   `Stopped` and carries the pending tag, the Lambda disables
   `DirectInternetAccess`/`RootAccess`, clears the tag, and (only if
   `auto_restart = true`) starts it back up.

By default the notebook is left **stopped** after remediation.

## Usage

```hcl
module "sagemaker_notebook_exposure_event_driven" {
  source = "github.com/DustyStudy/aws-ai-guardrails//terraform/sagemaker-notebook-exposure/event-driven"

  notification_email = "you@example.com"
  auto_restart        = false
}
```

Requires the `hashicorp/archive` provider in addition to `hashicorp/aws`.
Works the same in GovCloud — check SageMaker's availability in your
target GovCloud region first.

## Inputs

| Name | Description | Default |
|---|---|---|
| `name_prefix` | Prefix for all resource names | `sagemaker-notebook-exposure` |
| `notification_email` | Email to subscribe to the SNS topic (optional) | `""` |
| `auto_restart` | Restart the notebook after remediation | `false` |
| `code_signing_config_arn` | ARN of an existing code-signing config (optional) | `null` |

## Outputs

| Name | Description |
|---|---|
| `lambda_function_arn` | ARN of the remediation Lambda |
| `sns_topic_arn` | ARN of the SNS notification topic |

## Testing it

```bash
aws sagemaker create-notebook-instance \
  --notebook-instance-name test-exposure-check \
  --instance-type ml.t3.medium \
  --role-arn arn:aws:iam::ACCOUNT_ID:role/YourSageMakerExecutionRole \
  --direct-internet-access Enabled
```

Within a few minutes the notebook should get tagged, stopped, and
reconfigured with direct internet access disabled.

## Notes

- Deploy alongside `../config-rule/` to also catch pre-existing notebooks
  and drift — that path only covers direct internet access (there's no
  AWS Config managed rule for notebook root access yet), so this
  event-driven module is still the only coverage for newly-set root
  access.
