# bedrock-cost-guardrails (Terraform)

Guards against the most common real-world agentic AI incident: not a
breach, but an agent stuck in a loop calling itself or a tool
repeatedly, running up a large bill overnight before anyone notices.
Two complementary AWS-native cost controls, both scoped to Amazon
Bedrock — no Lambda involved.

## What this creates

1. **A monthly budget** (`aws_budgets_budget`) with a hard USD ceiling for
   Bedrock spend, notifying at 80% of actual spend and 100% of
   forecasted spend. Predictable, threshold-based — you set the number.
2. **Cost Anomaly Detection** (`aws_ce_anomaly_monitor` +
   `aws_ce_anomaly_subscription`), scoped to the Bedrock service via a
   custom monitor. This is ML-based against your account's own
   historical spend pattern, so it can catch a spike *before* it reaches
   the budget ceiling — the difference matters because a runaway agent
   loop overnight can blow past a monthly threshold in hours.

Both notify the same SNS topic.

## Usage

```hcl
module "bedrock_cost_guardrails" {
  source = "github.com/DustyStudy/aws-org-guardrails//modules/bedrock-cost-guardrails"

  notification_email       = "you@example.com"
  monthly_budget_limit_usd = 500
  anomaly_threshold_usd    = 50
}
```

Works the same in GovCloud, assuming Bedrock is available in your
GovCloud region.

## Inputs

| Name | Description | Default |
|---|---|---|
| `name_prefix` | Prefix for all resource names | `bedrock-cost-guardrails` |
| `notification_email` | Email to subscribe to the SNS topic (optional) | `""` |
| `monthly_budget_limit_usd` | Monthly USD ceiling for Bedrock spend | `500` |
| `anomaly_threshold_usd` | Dollar-impact threshold for an immediate anomaly alert | `50` |

## Outputs

| Name | Description |
|---|---|
| `sns_topic_arn` | ARN of the SNS topic used for cost alerts |
| `anomaly_monitor_arn` | ARN of the Bedrock cost anomaly monitor |
| `budget_name` | Name of the Bedrock monthly budget |

## Notes

- **Cost Anomaly Detection notifications require `frequency = "IMMEDIATE"`
  to use SNS** — `DAILY`/`WEEKLY` frequencies only support email
  subscribers. This module uses `IMMEDIATE` so alerts reach SNS (and
  anything you wire downstream of it — Slack, PagerDuty, a Lambda) as
  soon as an anomaly is detected, not batched into a daily digest.
- Cost Anomaly Detection needs some baseline spend history to establish
  what's "normal" before it can flag deviations — expect it to be less
  useful in the first few weeks after Bedrock usage starts.
- The budget's `cost_filter` scopes it to the "Amazon Bedrock" service
  specifically — spend from SageMaker, Bedrock Agents' underlying Lambda
  invocations, or other AI infrastructure isn't included. Duplicate this
  module with a different `cost_filter` value if you want the same
  pattern for other services.
- Set `monthly_budget_limit_usd` and `anomaly_threshold_usd` based on
  your actual expected usage — defaults are a starting point, not a
  recommendation for your workload's scale.
