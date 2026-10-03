# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this repository, please report it privately — **do not open a public GitHub issue**.

Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) feature (Security tab → "Report a vulnerability" on this repo). Please do not include real AWS account IDs, ARNs, or credentials in your report.

You can expect an initial response within 5 business days.

## Scope

This repository provides general-purpose (not FedRAMP-specific) AWS security Terraform modules for cloud security engineers, designed to work in both AWS commercial and AWS GovCloud. This includes automated remediation tooling, SCP guardrails, IAM Identity Center auditing, and a Wiz findings bridge. Reports in scope include:

- Logic errors in templates/automation that could weaken security posture (e.g. overly permissive IAM, unintended public exposure, remediation logic that fails open)
- Supply-chain concerns (malicious or unpinned dependencies, GitHub Actions)
- Secrets or credentials accidentally committed to this repo

Out of scope: vulnerabilities in AWS services themselves (report those to AWS), or issues in downstream forks/deployments not present in this repo's source.

## Supported Versions

This repository doesn't ship versioned releases — the `main` branch is the
single source of truth and the only branch that receives fixes.
