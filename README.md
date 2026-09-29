# aws-cloud-security-toolbox

[![Lint and Security Scan](https://github.com/DustyStudy/aws-cloud-security-toolbox/actions/workflows/lint-and-scan.yml/badge.svg)](https://github.com/DustyStudy/aws-cloud-security-toolbox/actions/workflows/lint-and-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![AWS](https://img.shields.io/badge/AWS-Commercial%20%2B%20GovCloud-orange)](#)

Practical CloudFormation and Terraform for cloud security engineers:
guardrails, auto-remediation, and detection templates for day-to-day AWS
security work. Every template is written to run in both **AWS commercial
and AWS GovCloud** (no hardcoded `arn:aws:...`, `${AWS::Partition}` / the
`aws_partition` data source is used throughout).

This is a general-purpose companion to [`fedramp-cfn-library`](https://github.com/DustyStudy/fedramp-cfn-library)
and [`fedramp-terraform-library`](https://github.com/DustyStudy/fedramp-terraform-library),
which focus specifically on FedRAMP Moderate/High/20x control mappings.
Templates here aren't tied to a specific compliance framework; they're
just useful guardrails.

Each auto-remediation template here is independent and standalone by
design: deploy the one you need with no other dependencies. For a
governed pipeline that routes *every* Security Hub finding through
policy-driven mode selection, blast-radius guardrails, human approval for
disruptive actions, and an audit trail exported as compliance evidence
(and that can dispatch to playbooks here, like
[`auto-remediate-open-ssh-rdp`](#auto-remediate-open-ssh-rdp) and
[`ec2-isolation-runbook`](#ec2-isolation-runbook), instead of duplicating
them), see [`aws-remediation-orchestrator`](https://github.com/DustyStudy/aws-remediation-orchestrator).

## Structure

Each tool/template lives in its own directory, mirrored under both
`cloudformation/` and `terraform/` where practical:

```
aws-cloud-security-toolbox/
├── cloudformation/
│   ├── auto-remediate-open-ssh-rdp/
│   │   ├── event-driven/       # EventBridge + CloudTrail, near real-time
│   │   ├── config-rule/        # AWS Config + SSM Automation, catches drift
│   │   └── lambda/             # shared Lambda source (CFN's own copy)
│   ├── scp-guardrails/         # deploys the SCPs below, attached to Organizations targets
│   ├── root-activity-alarm/    # EventBridge -> SNS on any root activity
│   ├── iam-credential-hygiene/ # scheduled deactivation of stale IAM keys
│   ├── identity-center-access-auditor/ # detective scan for over-privileged/misassigned Identity Center access
│   ├── ec2-isolation-runbook/  # on-demand SSM runbook to quarantine a compromised instance
│   ├── security-baseline-new-accounts/
│   │   ├── member-baseline/    # StackSet: GuardDuty+SecurityHub+Config for every account in an OU
│   │   └── organization-trail/ # one-time org-wide CloudTrail trail
│   ├── ai-ml-guardrails/        # deploys the AI/ML SCPs below, attached to Organizations targets
│   ├── bedrock-logging-enforcement/  # scheduled check/restore of Bedrock invocation logging
│   ├── ai-agent-iam-auditor/    # detective scan for over-permissioned Bedrock/SageMaker agent roles
│   ├── bedrock-cost-guardrails/ # Budget + Cost Anomaly Detection scoped to Bedrock spend
│   ├── sagemaker-notebook-exposure/
│   │   ├── event-driven/       # EventBridge + CloudTrail, near real-time
│   │   └── config-rule/        # AWS Config + SSM Automation, catches drift
│   ├── claude-apps-gateway/     # reference deployment of Anthropic's self-hosted gateway
│   │   ├── ecr/                 # phase 1: ECR repository
│   │   └── infrastructure/      # phase 2: RDS, ALB, ECS service, IAM, Secrets Manager
│   ├── stale-account-detector/  # org-wide CloudTrail Lake scan for unused accounts
│   └── wiz-finding-bridge/      # API Gateway + Lambda bridge for Wiz webhook findings
├── terraform/
│   ├── auto-remediate-open-ssh-rdp/
│   │   ├── event-driven/
│   │   ├── config-rule/
│   │   └── lambda/             # shared Lambda source (Terraform zips this)
│   ├── scp-guardrails/
│   ├── root-activity-alarm/
│   ├── iam-credential-hygiene/
│   ├── identity-center-access-auditor/
│   ├── ec2-isolation-runbook/
│   ├── security-baseline-new-accounts/
│   │   ├── member-baseline/
│   │   └── organization-trail/
│   ├── ai-ml-guardrails/
│   ├── bedrock-logging-enforcement/
│   ├── ai-agent-iam-auditor/
│   ├── bedrock-cost-guardrails/
│   ├── sagemaker-notebook-exposure/
│   │   ├── event-driven/
│   │   └── config-rule/
│   ├── claude-apps-gateway/     # same reference deployment, single module (2-phase apply)
│   ├── stale-account-detector/
│   └── wiz-finding-bridge/
└── policies/
    ├── scp-guardrails/          # standalone SCP JSON, usable without CFN/TF
    └── ai-ml-guardrails/        # standalone AI/ML SCP JSON, usable without CFN/TF
```

## Templates

| Module | Type | What it does |
|---|---|---|
| [`auto-remediate-open-ssh-rdp`](#auto-remediate-open-ssh-rdp) | Auto-remediation | Revokes security group rules that open SSH/RDP to the internet |
| [`scp-guardrails`](#scp-guardrails) | Preventive | SCP library: deny root, deny disabling security services, require IMDSv2, more |
| [`root-activity-alarm`](#root-activity-alarm) | Detective | Real-time alert on any root user activity |
| [`iam-credential-hygiene`](#iam-credential-hygiene) | Auto-remediation | Deactivates stale/unused IAM access keys |
| [`identity-center-access-auditor`](#identity-center-access-auditor) | Detective | Flags over-privileged or misassigned Identity Center permission sets |
| [`ec2-isolation-runbook`](#ec2-isolation-runbook) | On-demand response | Quarantines a suspected-compromised EC2 instance |
| [`security-baseline-new-accounts`](#security-baseline-new-accounts) | Preventive | Auto-enables GuardDuty/Config/Security Hub + an org CloudTrail on every account |
| [`ai-ml-guardrails`](#ai-ml-guardrails) | Preventive | SCP library protecting Bedrock logging and SageMaker notebook config |
| [`bedrock-logging-enforcement`](#bedrock-logging-enforcement) | Auto-remediation | Re-enables Bedrock invocation logging if it's disabled |
| [`ai-agent-iam-auditor`](#ai-agent-iam-auditor) | Detective | Flags over-permissioned IAM roles trusted by AI/agent services |
| [`bedrock-cost-guardrails`](#bedrock-cost-guardrails) | Detective | Budget ceiling + anomaly detection on Bedrock spend |
| [`sagemaker-notebook-exposure`](#sagemaker-notebook-exposure) | Auto-remediation | Locks down SageMaker notebooks with internet or root access enabled |
| [`claude-apps-gateway`](#claude-apps-gateway) | Reference | Deployment reference for Claude apps gateway on AWS |
| [`stale-account-detector`](#stale-account-detector) | Detective | Finds accounts with no CloudTrail activity in N days |
| [`wiz-finding-bridge`](#wiz-finding-bridge) | Detective | Bridges Wiz webhook findings into SNS and (optionally) your own remediation Lambdas |

### `auto-remediate-open-ssh-rdp`

Automatically revokes security group ingress rules that open **SSH (22)**
or **RDP (3389)** to the entire internet (`0.0.0.0/0` / `::/0`). Ships as
two complementary paths (deploy one or both):

- **`event-driven/`**: EventBridge rule matching CloudTrail's
  `AuthorizeSecurityGroupIngress` and `ModifySecurityGroupRules` events,
  revokes the offending rule within seconds of it being created or edited.
- **`config-rule/`**: AWS Config managed rule (`RESTRICTED_INCOMING_TRAFFIC`)
  + SSM Automation remediation, re-evaluates all security groups on a
  schedule and catches rules that existed before deployment or slipped
  past the event-driven path.

Both paths send an SNS notification on every remediation and share the
same Lambda logic. See each subdirectory's README for deployment
instructions.

### `scp-guardrails`

A library of preventive Service Control Policies: deny root user actions,
deny disabling CloudTrail/Config/GuardDuty/Security Hub, require IMDSv2,
deny leaving the Organization, deny disabling S3 Block Public Access, and
an optional region-restriction policy. Usable as standalone JSON from
`policies/scp-guardrails/`, or deployed/attached to Organizations targets
via `cloudformation/scp-guardrails/` or `terraform/scp-guardrails/`. See
`policies/scp-guardrails/README.md` for full usage of all three.

### `root-activity-alarm`

Fires an SNS notification within seconds of any root user activity:
console sign-in, API call, or AWS service event performed as root. No
Lambda involved; EventBridge invokes SNS directly. A detective complement
to the `deny-root-user` SCP: catches attempts even where the SCP blocks
them, and covers console sign-ins, which SCPs can't prevent.

### `iam-credential-hygiene`

Scans every IAM user's access keys on a schedule and **deactivates**
(never deletes) any key that's too old or unused for too long, notifying
via SNS. Closes one of the most common CIS Benchmark / Wiz / Security Hub
findings automatically instead of relying on someone reviewing a
credential report.

### `identity-center-access-auditor`

A scheduled, **detective-only** audit of AWS IAM Identity Center
(successor to AWS SSO): flags permission sets carrying
`AdministratorAccess` or risky wildcard inline-policy statements, flags
account assignments made directly to a user instead of a group, and
reports unused permission sets as an informational addendum. A single
over-privileged permission set assigned org-wide, or access tracked
person-by-person instead of through groups, is exactly the kind of
governance drift that's invisible until an audit (or an incident)
goes looking for it. Never modifies a permission set or assignment.
Deploy once, from the account where Identity Center is enabled (the
management account or a delegated administrator account).

### `ec2-isolation-runbook`

An **on-demand** SSM Automation runbook for incident response: tags a
suspected-compromised instance, snapshots every attached EBS volume for
forensics, swaps its security groups for a fully-isolated one, optionally
stops it, and notifies via SNS. Deliberately not automatic: isolating
the wrong instance on a false positive can itself cause an outage.

### `security-baseline-new-accounts`

Multi-account governance: ensures every account in an OU gets a security
baseline automatically, including accounts created later.

- **`member-baseline/`**: a CloudFormation StackSet (service-managed,
  auto-deployment) that enables GuardDuty, Security Hub, and AWS Config in
  every targeted account.
- **`organization-trail/`**: a single AWS Organization CloudTrail trail
  covering every account automatically. Deployed once, separately from
  the per-account baseline, since CloudTrail rejects a duplicate org trail
  per account.

### `ai-ml-guardrails`

A library of preventive Service Control Policies for AI/ML workloads:
protect Bedrock's audit trail (deny disabling invocation logging, deny
deleting Guardrails), optionally restrict Bedrock model invocation to an
allow-listed set of foundation models, and lock down SageMaker notebook
instances (no direct internet access, no root access, VPC required, KMS
encryption required). Same structure as `scp-guardrails`: standalone
JSON from `policies/ai-ml-guardrails/`, or deploy/attach via
`cloudformation/ai-ml-guardrails/` or `terraform/ai-ml-guardrails/`.

### `bedrock-logging-enforcement`

Checks the account's Bedrock model invocation logging configuration on a
schedule and re-enables it (to a managed S3 bucket and CloudWatch Logs
group) if it's missing or was disabled, notifying via SNS. This is the
only audit trail of what prompts/completions actually passed through
your models; pairs with `ai-ml-guardrails`'s logging-protection SCP for
a prevent-and-detect combination.

### `ai-agent-iam-auditor`

A scheduled, **detective-only** scan of every IAM role's trust policy for
AI/agent service principals (Bedrock, SageMaker, Amazon Q). Any matching
role carrying overly-broad permissions (full wildcard actions, a
service-wide wildcard on a sensitive service, or `AdministratorAccess`)
is flagged in an SNS summary. Never modifies anything: agentic workflows
often get built with broad "just in case" permissions, and an agent
steered into misusing them (via prompt injection or bad task design) has
a much larger blast radius than a human operator with the same role.

Also discovers and audits the Lambda execution roles behind every
Bedrock Agent's action groups, usually the higher-risk role of the two,
since it's what actually executes when the agent decides to act, and
it's invisible to the trust-policy scan alone (its own trust policy
names `lambda.amazonaws.com`, not Bedrock).

### `bedrock-cost-guardrails`

Guards against the most common real-world agentic AI incident: not a
breach, but an agent stuck in a loop calling itself or a tool
repeatedly, running up a large bill overnight before anyone notices. No
Lambda: combines a monthly AWS Budget (a hard, predictable ceiling on
Bedrock spend) with Cost Anomaly Detection (ML-based against your
account's own spend history, catching a spike before it reaches the
budget ceiling).

### `sagemaker-notebook-exposure`

Detects SageMaker notebook instances with **direct internet access** or
**root access** enabled, effectively an unmanaged EC2 instance with AWS
credentials attached, reachable from the internet, and remediates them.
Two-phase by necessity, since SageMaker only allows changing those
settings while a notebook is stopped:

- **`event-driven/`**: CloudTrail-triggered stop, then SageMaker's own
  "Notebook Instance State Change" event triggers the actual
  reconfiguration once the notebook has stopped.
- **`config-rule/`**: AWS Config managed rule
  (`SAGEMAKER_NOTEBOOK_NO_DIRECT_INTERNET_ACCESS`) + SSM Automation,
  catches pre-existing/drifted notebooks. Covers direct internet access
  only; there's no equivalent Config managed rule for root access yet,
  so `event-driven/` remains the only coverage for that.

### `claude-apps-gateway`

A reference deployment of the
[Claude apps gateway for AWS](https://aws.amazon.com/blogs/machine-learning/introducing-claude-apps-gateway-for-aws/):
Anthropic's self-hosted control plane that centralizes identity (via your
OIDC IdP), policy, telemetry, and spend caps for Claude Code and Claude
Desktop across an organization, routing inference to Amazon Bedrock so no
per-developer cloud credentials or long-lived secrets ever land on a
laptop. Mirrors
[Anthropic's own AWS deployment guide](https://code.claude.com/docs/en/claude-apps-gateway-on-aws)
closely: ECS Fargate, RDS for PostgreSQL (encrypted, TLS-only), Secrets
Manager, a least-privilege IAM task role scoped to exactly the Bedrock
Claude model ARNs, and an internal ALB. Deliberately split into an ECR
phase and an infrastructure phase: a single stack/apply can't create an
empty image repository, wait for a human to push an image, and then
stand up an ECS service that needs that image to exist. A working
example for customer-managed infrastructure, not a supported production
deployment, the same caveat Anthropic's own guide gives about its `aws` CLI
walkthrough.

### `stale-account-detector`

Scans every **ACTIVE** account in the Organization for CloudTrail
activity in the last N days, using an organization-wide **CloudTrail
Lake** event data store queried with plain SQL, no Athena/Glue setup
required. Emails a report via SNS only when it actually finds stale
accounts; a clean scan sends nothing. An account with only automated API
activity but no interactive console sign-in is called out separately in
the report as context, not conflated with genuine staleness. Complements
[`security-baseline-new-accounts`](#security-baseline-new-accounts),
which handles the other end of the account lifecycle; this tool is
about the accounts that quietly stopped being used.

### `wiz-finding-bridge`

Receives Wiz webhook deliveries via an API Gateway HTTP API and bridges
them into this repo's existing patterns: an SNS notification, and
optionally an invocation of a remediation Lambda you supply (an adapter
is needed; this repo's own remediators don't accept the bridge's payload)
when a finding matches a configured mapping. **Schema-tolerant by
design**: Wiz's webhook JSON shape is read via configurable dot-notation
field paths rather than hardcoded keys, and the raw payload is always
included in the notification so the correct paths can be identified from
a real finding rather than guessed. Authenticates deliveries via a long
random secret embedded in the webhook URL path, matching the only
configuration surface Wiz's basic Webhook integration exposes (a
destination URL, no custom headers). See the module README before
relying on this in production: it needs a short tuning pass against a
real Wiz payload first.

## Proof

`security-baseline-new-accounts` (the `member-baseline` StackSet) has been
run for real against a real AWS Organization, verified against AWS's own
records, and torn down cleanly. See [`docs/PROOF.md`](docs/PROOF.md). The
rest of the toolbox has not yet been tested this way; treat that
distinction as real, not a formality.

## CI

GitHub Actions on every push/PR:
- **CloudFormation**: `cfn-lint` + Checkov
- **Terraform**: `terraform fmt -check`, `terraform validate`, `tflint`,
  Checkov
- **Python and policies**: Lambda sources compile, `policies/**/*.json`
  parses, and each Lambda's CloudFormation and Terraform copies are
  byte-identical

## Contributing

PRs welcome. New templates should:
- Support both AWS commercial and GovCloud partitions
- Include a README with what it does, how it works, and deployment steps
- Pass the existing CI (lint + Checkov) before merge
