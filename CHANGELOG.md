# Changelog

All notable changes to this repo are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the repo uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-09-29

First tagged release, after the repo was refocused on AI and ML guardrails.

### Added
- `ai-ml-guardrails`: SCPs that deny disabling Bedrock invocation logging or
  deleting Bedrock Guardrails, lock down SageMaker notebooks (no direct
  internet, no root access, VPC required), require KMS keys for SageMaker
  notebooks and training jobs, and an opt-in Bedrock foundation-model
  allow-list that keeps inference profiles usable.
- `bedrock-logging-enforcement`: scheduled check that re-enables Bedrock
  model invocation logging when it is off or points somewhere else.
- `ai-agent-iam-auditor`: detective scan for over-permissioned IAM roles
  trusted by AI services or behind Bedrock Agent action groups.
- `bedrock-cost-guardrails`: AWS Budget and Cost Anomaly Detection scoped to
  Bedrock spend.
- `sagemaker-notebook-exposure`: event-driven (EventBridge + CloudTrail) and
  AWS Config + SSM Automation remediation for exposed notebook instances.
- `claude-apps-gateway`: reference deployment of the self-hosted Claude apps
  gateway, running as a non-root container.
- Standalone SCP JSON in `policies/ai-ml-guardrails/` for use without
  Terraform.
- Tests: a plan-time `terraform test` suite for `ai-ml-guardrails` (8 runs,
  including a check that the standalone JSON matches the module) and pytest
  suites for the three Lambdas (24 tests).
- `docs/PROOF.md`: what each check verifies, the numbers from the last run,
  IAM Access Analyzer results for the SCPs, and the gaps.
- CI: `terraform fmt`, `validate`, `test`, TFLint, Checkov, pytest, policy
  JSON parsing, Gitleaks and Trivy.

### Changed
- **Breaking:** the repo was renamed from `aws-cloud-security-toolbox`. The
  general AWS modules moved to `aws-remediation-orchestrator` and
  `fedramp-terraform-library`; the README maps each one to its new home.
- **Breaking:** Terraform only. The CloudFormation templates were removed.

[Unreleased]: https://github.com/DustyStudy/aws-ai-guardrails/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/DustyStudy/aws-ai-guardrails/releases/tag/v0.1.0
