# security-baseline-new-accounts / member-baseline (Terraform)

A CloudFormation **StackSet** — managed through Terraform — that enables
GuardDuty, Security Hub, and AWS Config in every account within a target
Organizational Unit, including accounts created *after* this is applied.
This is the fix for "the new account got missed" in multi-account
governance.

Terraform has no native concept of "watch for new accounts and
auto-apply" - StackSets with `SERVICE_MANAGED` permissions and
auto-deployment is the AWS-native mechanism for that, so this module
orchestrates a StackSet rather than reinventing that logic. The
per-account resources themselves are a small CloudFormation template
(`baseline-template.yaml`) that Terraform hands to the StackSet - you
don't need to touch CloudFormation directly, but it's worth knowing it's
there if you want to see or modify exactly what gets deployed per account.

## Prerequisites

1. Trusted access for CloudFormation StackSets enabled for your
   Organization:
   ```bash
   aws organizations enable-aws-service-access \
     --service-principal member.org.stacksets.cloudformation.amazonaws.com
   ```
2. CloudFormation's own Organizations access activated in the account you
   apply from. This is separate from step 1 and easy to miss - without it,
   `CreateStackSet` fails with `You must enable organizations access to
   operate a service managed stack set`:
   ```bash
   aws cloudformation activate-organizations-access
   ```
3. Apply from the **Organizations management account**, or from an
   account registered as a delegated administrator for CloudFormation
   StackSets (set `call_as = "DELEGATED_ADMIN"` in that case).

## Usage

```hcl
module "security_baseline" {
  source = "github.com/DustyStudy/aws-cloud-security-toolbox//terraform/security-baseline-new-accounts/member-baseline"

  target_organizational_unit_ids = ["ou-abcd-11111111"]
  regions                        = ["us-east-1"]
}
```

For GovCloud:

```hcl
  regions = ["us-gov-west-1", "us-gov-east-1"]
```

## What gets deployed in each member account

- **GuardDuty** — a detector, 15-minute finding publish frequency.
- **Security Hub** — enabled with the default standards.
- **AWS Config** — a configuration recorder + delivery channel, backed by
  a per-account, per-region S3 bucket (`aws-config-<account-id>-<region>`)
  with public access fully blocked and SSE-S3 encryption.

## Inputs

| Name | Description | Default |
|---|---|---|
| `name_prefix` | Prefix for the StackSet name | `security-baseline` |
| `target_organizational_unit_ids` | OU ID(s) to deploy the baseline to | — (required) |
| `regions` | Region(s) to enable the baseline in per account | `["us-east-1"]` |
| `call_as` | `SELF` (management account) or `DELEGATED_ADMIN` | `SELF` |

## Outputs

| Name | Description |
|---|---|
| `stack_set_name` | Name of the member-account-baseline StackSet |

## Notes

- **`IncludeGlobalResourceTypes` is deliberately `false`** in
  `baseline-template.yaml`, because the same template is applied in every
  region listed in `regions` — if it were `true` everywhere, IAM and
  other global resources would be recorded multiple times per account.
  See the file's comments if you want global resource tracking in one
  designated region.
- This does **not** set up CloudTrail — see the sibling
  `../organization-trail/` module. An AWS Organization trail is a single
  resource that covers every account automatically; it doesn't fit the
  per-account StackSet pattern.
- `retain_stacks_on_account_removal = false` means the baseline stack
  (and its Config S3 bucket) is deleted if an account leaves the target
  OU. Change this in `main.tf` if you'd rather retain the Config history
  for departed accounts.
- One `aws_cloudformation_stack_set_instance` is created per region in
  `regions` (via `for_each`), each targeting the same OU list.
- **One AWS Config recorder and delivery channel per region per account.**
  If a targeted account already has Config enabled (for example accounts
  enrolled through AWS Control Tower, or set up by hand), creating the
  baseline's recorder fails in that account and region. Exclude those OUs,
  or remove the existing recorder first.

## Proof

Run for real against a real AWS Organization - deployed via this Terraform
module through the StackSet mechanism it's actually designed for, then verified and torn down. See
[`docs/PROOF.md`](../../../docs/PROOF.md).
