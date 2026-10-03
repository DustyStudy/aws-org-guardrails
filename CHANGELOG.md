# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- AI and ML guardrails from `aws-ai-guardrails` (v0.2.1), with git history:
  `ai-ml-guardrails`, `ai-agent-iam-auditor`, `bedrock-cost-guardrails`,
  `bedrock-logging-enforcement`, `sagemaker-notebook-exposure` and
  `claude-apps-gateway` under `modules/`, standalone SCP JSON under
  `policies/ai-ml-guardrails/`, Lambda tests under `tests/lambdas/`, and
  `docs/PROOF-AI-ML.md`. Module sources change from
  `aws-ai-guardrails//terraform/<name>` to `aws-org-guardrails//modules/<name>`.
  That repo's own changelog is in this repo's history at
  `_ai/CHANGELOG.md` in commit `4367e71`.

### Changed

- AI/ML modules: the SNS topics in `ai-agent-iam-auditor`,
  `bedrock-logging-enforcement` and both `sagemaker-notebook-exposure`
  variants are encrypted with each module's existing rotating CMK instead
  of the AWS-managed `alias/aws/sns` key.
- `bedrock-logging-enforcement`: the invocation-log bucket uses SSE-KMS
  with the module's CMK. The old comment said Bedrock couldn't deliver to
  SSE-KMS buckets; AWS documents that it can, given a `kms:GenerateDataKey`
  grant to `bedrock.amazonaws.com`, which the key policy now has. Redeploying
  changes the default encryption for new objects only.
- `claude-apps-gateway`: inline Trivy ignores, with reasons, for the
  port-443 egress rule and the SSE-S3 ALB log bucket (ALB access logs
  support only SSE-S3).

- `data-and-compute` bundle: `DenyExternalResourceShares` blocks creating
  or updating a RAM resource share that allows principals outside the
  organization, and `DenyAssociateToExternalShares` blocks adding
  resources or principals to a share that already allows them. Exempt
  roles can still share externally.
- Live proof: `proof/main.tf` deploys the guardrails to a sandbox OU and
  `proof/probe.py` checks them with real API calls, recording which policy
  type denied each one. First run: 31 of 31 probes matched
  ([docs/PROOF.md](docs/PROOF.md)).

## [0.2.1] - 2026-09-29

### Fixed

- Permissions boundary could not be created: IAM's `CreatePolicy` rejects a
  policy variable in the account field of a resource ARN ("The policy failed
  legacy parsing"), which IAM Access Analyzer and the policy simulator both
  accept. Resource and NotResource ARNs now use `*` for the account; the
  `iam:PermissionsBoundary` condition keeps `${aws:PrincipalAccount}`.
- The test evaluator now rejects a policy variable in a resource ARN's
  account field, matching IAM.

## [0.2.0] - 2026-09-29

### Security

- The protected-role statement now also denies `iam:CreateRole`. Before,
  anyone in a member account could create a role named like an exempt
  principal (for example `security-breakglass`) and inherit its exemption.

### Changed

- The `policies` module rejects an exempt role whose name does not start
  with one of `protected_role_name_prefixes`. Callers that exempt a role
  outside those prefixes must add a matching prefix.

## [0.1.1] - 2026-09-29

### Fixed

- Permissions boundary: the broad Allow no longer covers `iam:PassRole` or
  `iam:CreateServiceLinkedRole`. PassRole is granted only for roles under the
  delegated path, and service-linked roles only for the services in the new
  `service_linked_role_services` input. IAM Access Analyzer had reported a
  SECURITY_WARNING for PassRole on `*`; it now reports 0 findings on every
  policy in the commercial and GovCloud partitions.

## [0.1.0] - 2026-09-29

### Added

- `policies` module: four SCP bundles (`core`, `security-services`,
  `data-and-compute`, `region-restriction`) and an account-agnostic
  permissions boundary, rendered without a provider.
- `scp-baseline` module: creates and attaches the bundles, with plan-time
  checks for the 5-SCPs-per-target limit and unknown bundle names.
- `permission-boundary` module: creates the boundary policy in a member account.
- `identity-center` module: permission sets that require a permissions
  boundary unless explicitly exempted, plus group assignments.
- Commercial and GovCloud examples.
- Policy behavior tests on a strict IAM evaluator, `terraform test` suites
  for every module, and an IAM Access Analyzer validation script.
- CI: fmt, validate, TFLint, terraform test on Terraform 1.9 and 1.16,
  ruff, pytest, Checkov, Trivy and Gitleaks.

[0.2.1]: https://github.com/DustyStudy/aws-org-guardrails/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/DustyStudy/aws-org-guardrails/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/DustyStudy/aws-org-guardrails/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/DustyStudy/aws-org-guardrails/releases/tag/v0.1.0
