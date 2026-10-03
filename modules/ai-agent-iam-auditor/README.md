# ai-agent-iam-auditor (Terraform)

Scans every IAM role's trust policy for AI/agent service principals
(Bedrock, SageMaker, Amazon Q) on a schedule, and for any matching role,
flags overly-broad attached/inline permissions. **Detective only** — never
modifies anything.

## The risk this targets

Agentic AI workflows often get built by handing the agent's execution
role broad permissions "to get it working." That's a much larger blast
radius than a human operator with the same role, because the agent can be
steered — via prompt injection, a bad task description, or an overzealous
framework default — into calling any API the role permits, at machine
speed, with no human in the loop.

## How it works

There are two independent discovery paths, because they catch different roles:

**1. Trust-policy scan**
1. A scheduled EventBridge rule (default: daily, via `schedule_expression`)
   invokes the Lambda.
2. The Lambda lists every IAM role and checks each one's trust policy for
   a `Principal.Service` matching `ai_service_principals`.

**2. Bedrock Agent action-group scan**
3. Separately, the Lambda lists every Bedrock Agent and, for each one's
   `DRAFT` version, lists its action groups. Each action group backed by
   a Lambda executor has that Lambda's execution role resolved and added
   to the scan. This matters because an Agent's *own* role is often
   fairly narrow, but its action groups hand real execution off to
   separate Lambda functions — and those Lambdas' execution roles are
   trusted by `lambda.amazonaws.com`, not Bedrock, so they're invisible
   to the trust-policy scan even though they're what actually runs when
   the agent decides to act. Set `check_bedrock_agent_action_groups = false`
   to disable this path.

**Both paths converge on the same check:** for every discovered role, the
Lambda inspects attached AWS-managed and inline policies for a full
wildcard action, a service-wide wildcard on one of
`sensitive_wildcard_services` combined with `Resource: "*"`, or the
`AdministratorAccess` managed policy. Any role with findings is included
in a single SNS summary, noting how it was discovered.

## Usage

```hcl
module "ai_agent_iam_auditor" {
  source = "github.com/DustyStudy/aws-org-guardrails//modules/ai-agent-iam-auditor"

  notification_email = "you@example.com"
}
```

Requires the `hashicorp/archive` provider in addition to `hashicorp/aws`.
Works the same in GovCloud.

## Inputs

| Name | Description | Default |
|---|---|---|
| `name_prefix` | Prefix for all resource names | `ai-agent-iam-auditor` |
| `notification_email` | Email to subscribe to the SNS topic (optional) | `""` |
| `schedule_expression` | EventBridge schedule | `rate(1 day)` |
| `ai_service_principals` | Trust-policy service principals treated as "AI/agent" | Bedrock, SageMaker, Q, Q Business |
| `sensitive_wildcard_services` | Services where `<service>:*` + `Resource: "*"` is flagged | iam, ec2, s3, kms, organizations, sts |
| `check_bedrock_agent_action_groups` | Also audit Bedrock Agent action-group Lambda roles | `true` |
| `code_signing_config_arn` | ARN of an existing code-signing config (optional) | `null` |

## Outputs

| Name | Description |
|---|---|
| `lambda_function_arn` | ARN of the auditor Lambda |
| `sns_topic_arn` | ARN of the SNS notification topic |

## Notes

- The Bedrock Agent action-group scan only checks each agent's **`DRAFT`**
  version. A production agent invoked via an alias pointing at a
  different, published version could have action groups the DRAFT
  version doesn't reflect — a known scope limitation. If your org
  publishes agent versions independently from DRAFT and wants this
  covered, extend the Lambda to also call `ListAgentAliases`/
  `GetAgentVersion` for each alias's target version.
- Only **AWS-managed** policies are evaluated by default (the Lambda's
  IAM permissions are scoped to `arn:...:iam::aws:policy/*`). If your org
  attaches customer-managed policies to AI/agent roles too, broaden the
  `iam:GetPolicy`/`iam:GetPolicyVersion` resource scope in `main.tf`.
- Purely additive to [`ai-ml-guardrails`](../ai-ml-guardrails/): the SCPs
  govern what AI services can do account-wide; this audits what specific
  agent roles can do, which SCPs generally can't see into.
- False positives are expected — the point is visibility, not a hard gate.
