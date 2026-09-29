# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

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

[0.1.1]: https://github.com/DustyStudy/aws-org-guardrails/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/DustyStudy/aws-org-guardrails/releases/tag/v0.1.0
