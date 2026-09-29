# Live proof

The guardrails were deployed to a real AWS organization on 2026-09-29 and
probed with real API calls. This page records how, what happened, and what
the run did not cover. Account IDs are replaced with `111122223333`.

## Setup

- **Target:** a new OU holding one otherwise empty member account, with the
  four SCP bundles attached next to FullAWSAccess (5 of 5 SCP slots).
- **Configuration:** the same settings planned for the organization-wide
  rollout: allowed regions `us-east-1`, `us-east-2`, `us-west-2`, and four
  exempt roles (`security-breakglass`, `security-pipeline`, the Prowler scan
  role and the StackSets execution role), each also covered by a protected
  prefix.
- **Code:** [`proof/main.tf`](../proof/main.tf) at v0.2.1. It creates the
  boundary and two test roles in the member account before attaching the
  SCPs, because afterwards nobody in the account can create a `security-*`
  role. The account is moved between OUs with the AWS CLI rather than
  Terraform, so a `terraform destroy` can never remove it from the
  organization.
- **Probes:** [`proof/probe.py`](../proof/probe.py), run as three principals
  in the member account:

  | Principal | Identity policy | Boundary | SCP exempt |
  |-----------|-----------------|----------|:---:|
  | `workload` | AdministratorAccess (the account's Identity Center admin session) | none | No |
  | `app-deployer` | AdministratorAccess | `workload-permissions-boundary` | No |
  | `breakglass` | AdministratorAccess | none | Yes |

Every probe is designed to change nothing when the guardrail works: EC2 calls
use DryRun, and other calls target resources that do not exist, so a request
that gets past the policies fails with NotFound instead of acting. The one
probe that needs a real resource (changing instance metadata options) runs
against a `t3.nano` launched with IMDSv2 for the purpose and terminated
afterwards.

AWS names the policy type in most AccessDenied messages ("with an explicit
deny in a service control policy"). EC2 returns an encoded message instead,
which `sts:DecodeAuthorizationMessage` turns into the matching statement.

## Results: 31 of 31 probes matched

| Principal | Request | Expected | Result | Detail | |
|---|---|---|---|---|---|
| workload | cloudtrail:StopLogging | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| breakglass | cloudtrail:StopLogging | not denied | not denied | TrailNotFoundException (reached the service; not denied by policy) | pass |
| workload | config:StopConfigurationRecorder | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| breakglass | config:StopConfigurationRecorder | not denied | not denied | NoSuchConfigurationRecorderException (reached the service; not denied by policy) | pass |
| workload | guardduty:DeleteDetector | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| workload | access-analyzer:DeleteAnalyzer | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| workload | iam:CreateAccessKey | scp | scp | AccessDenied: explicit deny in a service control policy | pass |
| breakglass | iam:CreateAccessKey | not denied | not denied | NoSuchEntity (reached the service; not denied by policy) | pass |
| workload | iam:CreateRole security-* (exempt-looking name) | scp | scp | AccessDenied: explicit deny in a service control policy | pass |
| workload | iam:UpdateAssumeRolePolicy on security-breakglass | scp | scp | AccessDenied: explicit deny in a service control policy | pass |
| workload | account:EnableRegion | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| workload | ec2:RunInstances without IMDSv2 | scp | scp | UnauthorizedOperation: explicit deny in a service control policy | pass |
| workload | ec2:RunInstances with IMDSv2 | not denied | not denied | DryRunOperation (would succeed) | pass |
| workload | ec2:DisableEbsEncryptionByDefault | scp | scp | UnauthorizedOperation: explicit deny in a service control policy | pass |
| breakglass | ec2:DisableEbsEncryptionByDefault | not denied | not denied | DryRunOperation (would succeed) | pass |
| workload | s3:PutAccountPublicAccessBlock | scp | scp | AccessDenied: explicit deny in a service control policy | pass |
| workload | ec2:DescribeInstances in us-east-1 | not denied | not denied | succeeded | pass |
| workload | ec2:DescribeInstances in us-east-2 | not denied | not denied | succeeded | pass |
| workload | ec2:DescribeInstances in eu-west-1 | scp | scp | UnauthorizedOperation: explicit deny in a service control policy | pass |
| workload | iam:ListRoles via eu-west-1 (global service) | not denied | not denied | succeeded | pass |
| breakglass | ec2:DescribeInstances in eu-west-1 | not denied | not denied | succeeded | pass |
| app-deployer | iam:CreateRole under /workload/ with the boundary | not denied | not denied | succeeded | pass |
| app-deployer | iam:CreateRole without the boundary | boundary | boundary | AccessDenied: denied by permissions boundary | pass |
| app-deployer | iam:CreateRole outside /workload/ | boundary | boundary | AccessDenied: denied by permissions boundary | pass |
| app-deployer | iam:DeleteRolePermissionsBoundary on itself | boundary | boundary | AccessDenied: denied by permissions boundary | pass |
| app-deployer | iam:CreatePolicyVersion on the boundary policy | boundary | boundary | AccessDenied: denied by permissions boundary | pass |
| app-deployer | organizations:DescribeOrganization | denied, type not named | denied, type not named | AccessDeniedException: You don't have permissions to access this resource. | pass |
| workload | organizations:DescribeOrganization | not denied | not denied | succeeded | pass |
| app-deployer | s3:ListAllMyBuckets | not denied | not denied | succeeded | pass |
| workload | ec2:ModifyInstanceMetadataOptions (IMDSv1 downgrade) | scp | scp | UnauthorizedOperation: explicit deny in a service control policy | pass |
| breakglass | ec2:ModifyInstanceMetadataOptions (IMDSv1 downgrade) | not denied | not denied | DryRunOperation (would succeed) | pass |

Organizations does not say which policy type denied a request. The paired
probes show the permissions boundary is the difference: the same call
succeeds for `workload` (no boundary) and is denied for `app-deployer` (same
AdministratorAccess identity policy, plus the boundary).

## What the live run caught

Two real defects were found on the way to this run. Neither showed up in the
unit tests, Access Analyzer or the policy simulator.

1. **Exempt role names could be claimed** (fixed in v0.2.0). Planning the
   rollout showed that the SCPs exempted roles by name but did not deny
   `iam:CreateRole` on those names, so any administrator in a member account
   could create `security-breakglass` and inherit its exemption. The probe
   `iam:CreateRole security-*` above confirms the fix live.
2. **The boundary could not be created** (fixed in v0.2.1). The first
   `terraform apply` failed with `MalformedPolicyDocument: The policy failed
   legacy parsing`. IAM does not accept a policy variable in the account field
   of a resource ARN, although Access Analyzer and the simulator both do. See
   [DESIGN.md](DESIGN.md#what-the-first-live-deployment-caught).

Two probes also had to be redesigned, which is worth knowing for anyone
writing similar tests: EC2 validates that an instance exists before it
checks authorization, and Organizations does not name the policy type in its
AccessDenied message.

## Not covered by this run

- `organizations:LeaveOrganization`: not probed, because a guardrail bug
  would have acted on the real account. Covered by the offline tests.
- The member account root user: no root credentials were used. Covered by
  the offline tests.
- The `identity-center` module: not deployed; it is covered by `terraform
  test` only.
- GovCloud: the rendered GovCloud policies pass Access Analyzer with 0
  findings, but they were not deployed.

## Reproducing

```sh
aws organizations create-organizational-unit --parent-id <root> --name guardrails-sandbox
aws organizations move-account --account-id <sandbox> --source-parent-id <old-parent> --destination-parent-id <sandbox-ou>

cd proof
cp terraform.tfvars.example terraform.tfvars   # set profiles and the OU
terraform init && terraform apply

python probe.py --profile <sandbox-admin> --launch-instance   --breakglass-role "$(terraform output -raw breakglass_role_arn)"   --app-deployer-role "$(terraform output -raw app_deployer_role_arn)"   --boundary-policy "$(terraform output -raw boundary_policy_arn)"

terraform destroy   # then move the account back and delete the OU
```
