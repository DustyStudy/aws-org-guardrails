# scp-guardrails (Terraform)

Deploys the SCP library in [`policies/scp-guardrails/`](../../policies/scp-guardrails/)
and attaches them to the Organizations targets (OUs, accounts, or the
root) you specify — `deny-root-user`, `deny-disable-security-services`,
`require-imdsv2`, `deny-leave-organization`,
`deny-disable-s3-public-access-block`, and an optional `restrict-regions`.

Full policy descriptions, variables, and GovCloud notes live in
[`policies/scp-guardrails/README.md`](../../policies/scp-guardrails/README.md#using-terraform) —
this directory just holds the module (`main.tf`, `variables.tf`,
`outputs.tf`, `versions.tf`).

Quick start:

```hcl
module "scp_guardrails" {
  source = "github.com/DustyStudy/aws-cloud-security-toolbox//terraform/scp-guardrails"

  target_ids              = ["ou-abcd-11111111", "123456789012"]
  enable_restrict_regions = true
  allowed_regions         = ["us-gov-west-1", "us-gov-east-1"]
}
```

Every policy has a matching `enable_*` boolean variable — see
`variables.tf`.
