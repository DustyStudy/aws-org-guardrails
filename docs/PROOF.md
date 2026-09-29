# Proof that security-baseline-new-accounts works

Run for real against a real AWS Organization on **2026-09-22**, then checked
against AWS's own records (GuardDuty, Security Hub, and Config APIs read
directly in the target account) rather than only against Terraform's own
output. Account IDs and the OU ID are masked below and in the evidence
files; they're not secret, just not worth publishing.

Only `security-baseline-new-accounts` / `member-baseline` has been tested
this way so far. The rest of this toolbox has not — see the README's
top-level Proof section.

## What was tested

| | |
|---|---|
| **Org** | One AWS Organization: a management account, and a dedicated single-account OU already used for earlier account-bootstrapping tests |
| **Target** | `member-baseline`'s StackSet, applied via this repo's Terraform module (not the standalone CloudFormation template) |
| **Method** | `terraform apply` from the Organizations management account; GuardDuty/Security Hub/Config APIs read directly in the target member account before, during, and after; teardown re-verified the same way |

## 1. Claims and evidence

| # | Claim | Result | Evidence |
|---|---|---|---|
| 1 | The StackSet deploys via `SERVICE_MANAGED` auto-deployment to every account in a target OU | **Proven** | [`stackset-instance-status.json`](proof/stackset-instance-status.json): instance status `CURRENT` / `SUCCEEDED` for the target account, `OrganizationalUnitId` matching the target OU |
| 2 | GuardDuty, Security Hub, and AWS Config all come up in the target account | **Proven** | [`member-account-state.json`](proof/member-account-state.json): all three unset before, all three enabled and recording after |
| 3 | The Config recorder actually records (not just created) | **Proven** | Same file: `describe-configuration-recorder-status` shows `"recording": true, "lastStatus": "SUCCESS"` |
| 4 | The Config S3 bucket is created with the documented name and is reachable | **Proven** | Same file: `HEAD` on `aws-config-<account-id>-us-east-1` returns 200 before teardown |
| 5 | Tearing down removes everything, including the S3 bucket | **Proven** | Same file, `after_destroy`: all three services unset again, bucket `HEAD` returns 404, StackSet gone from `list-stack-sets` in the management account |
| 6 | The module's documented prerequisites are sufficient to deploy | **Disproven, then fixed** | [`prerequisite-gap.json`](proof/prerequisite-gap.json): `CreateStackSet` failed with only the README's original single prerequisite applied; needed a second, undocumented one |

## 2. What running it for real found

Neither `terraform validate`, `tflint`, nor Checkov catch either of these — they're runtime/environment gaps, not code defects visible from the plan.

| Found | By | Fixed |
|---|---|---|
| `CreateStackSet` requires `cloudformation:ActivateOrganizationsAccess` in the calling account in addition to the Organizations-side trusted access the README already documented. Without it: `ValidationError: You must enable organizations access to operate a service managed stack set` | The first real `terraform apply` | README Prerequisites (this proof's commit); `docs/proof/prerequisite-gap.json` has the exact error and fix |
| `aws_cloudformation_stack_set_instance`'s `region` argument is deprecated in AWS provider v6 (`Use stack_set_instance_region instead`) — still worked, but every apply printed a warning | `terraform plan` output during this test | `main.tf`, this proof's commit |
| The Config bucket isn't empty by the time you'd tear it down — Config writes a `ConfigWritabilityCheckFile` on first recorder start within seconds, and the bucket has versioning on. A plain `terraform destroy` (or `aws s3 rb`) fails against a non-empty versioned bucket | Reading the bucket's object versions before attempting teardown | Not a code fix — documented in section 3 below, since retaining the bucket is the module's own documented default (`retain_stacks_on_account_removal`) and emptying it is an operator step, not something the module should do silently |

## 3. What this does not prove

- **New-account auto-deployment.** `auto_deployment.enabled = true` is meant to catch accounts added to the OU *after* the StackSet exists. This run created the StackSet against an OU that already contained its one account — the "add an account later and watch it get baselined automatically" path was not exercised.
- **Multi-region.** Only `regions = ["us-east-1"]` was tested. The `for_each` over multiple regions, and the `IncludeGlobalResourceTypes: false` reasoning for avoiding duplicate global-resource recording, rest on reading the code, not on a multi-region run.
- **`call_as = "DELEGATED_ADMIN"`.** Applied as `SELF` from the management account only; the delegated-administrator path is untested.
- **GovCloud.** Not exercised; the README's GovCloud region example was not run.
- **Clean teardown of a bucket with real Config history.** This test's bucket held one empty check file. A bucket with weeks of Config snapshots would need the same emptying step at a larger scale; not measured here.
- **Failure/rollback behavior.** `failure_tolerance_percentage = 20` was never exercised — every target account in this test succeeded, so partial-failure handling across an OU with multiple accounts is unverified.
- **Cost.** Real GuardDuty/Security Hub/Config charges accrued for the ~1 hour the stack was live in one account; not measured or reported here, and would scale with account count and Config's per-configuration-item pricing in real use.
- **One account, one OU.** Everything above is shown in one member account. Nothing here says the auto-deployment behavior holds at OU sizes beyond one account.

## 4. Reproduce it

Prerequisites: an AWS Organization; management-account credentials; a
throwaway OU with at least one member account you're fine enabling
GuardDuty/Security Hub/Config in temporarily.

1. `aws organizations enable-aws-service-access --service-principal member.org.stacksets.cloudformation.amazonaws.com`
2. `aws cloudformation activate-organizations-access` (see section 2 — this is the gap the README was missing)
3. Apply the `member-baseline` module against your test OU:
   ```hcl
   module "security_baseline" {
     source                          = "github.com/DustyStudy/aws-cloud-security-toolbox//terraform/security-baseline-new-accounts/member-baseline"
     target_organizational_unit_ids = ["<your-test-ou-id>"]
     regions                         = ["us-east-1"]
   }
   ```
4. In the target member account, confirm: `aws guardduty list-detectors`, `aws securityhub describe-hub`, `aws configservice describe-configuration-recorder-status` — all three should show enabled/recording within a couple of minutes.
5. Tear down: empty the `aws-config-<account-id>-<region>` bucket's object versions first (`aws s3api list-object-versions` / `delete-object --version-id`), then `terraform destroy`.
6. Re-check step 4's three commands — all should be back to unset, and the S3 bucket should 404.

`docs/proof/` holds the machine-readable evidence from the run above.
