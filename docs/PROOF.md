# Live proof

The guardrails were deployed to a real AWS organization and probed with
real API calls, twice: the baseline SCPs and the permissions boundary on
2026-09-29, and the AI/ML SCPs, the newer baseline statements and the
`identity-center` module on [2026-10-06](#run-2-2026-10-06-aiml-scps-newer-statements-and-identity-center).
This page records how, what happened, and what the runs did not cover.
Account IDs are replaced with `111122223333`.

## Run 1 (2026-09-29): baseline SCPs and the permissions boundary

### Setup

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

### Results: 31 of 31 probes matched

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

### What the live run caught

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

## Run 2 (2026-10-06): AI/ML SCPs, newer statements and Identity Center

A second run covered what run 1 did not: the five `ai-ml-guardrails` SCPs,
the statements added to the baseline since run 1 (Amazon SES for IAM users
and external AWS RAM shares) and the `identity-center` module. By then the
baseline was attached at the organization root, so this run also shows the
proof working under an organization-wide rollout.

### Setup

- **Target:** an OU holding one member account. The OU carries the current
  `core` and `data-and-compute` bundles with `deny_ses_to_iam_users` on,
  plus the Bedrock logging and model allow-list SCPs. The account itself
  carries the two SageMaker SCPs and the Bedrock deny for IAM users. AWS
  allows five SCPs per target, so nine policies need two targets.
- **Exempt role:** `security-breakglass` is deployed from the management
  account with a service-managed StackSet. Nobody inside the account can
  create it once the baseline is attached, and the StackSets execution role
  is one of the exempt principals, which is how a real rollout creates it.
- **Identity Center:** one permission set with AdministratorAccess, an
  inline deny of one read-only action, and `workload-permissions-boundary`
  as a customer managed boundary, assigned to one user in the account.
- **Code:** [`proof/run2/main.tf`](../proof/run2/main.tf) and
  [`proof/run2/probe.py`](../proof/run2/probe.py).
- **Principals:** `workload` and `breakglass` as in run 1; `iam-user`, an IAM
  user the exempt role creates for the run, allowed `bedrock:*` and `ses:*`
  by its identity policy; and `sso`, a session signed in through the new
  permission set.

### Service control policies: 27 of 27 probes matched

| Principal | Request | Expected | Result | Detail | |
|---|---|---|---|---|---|
| workload | bedrock:DeleteModelInvocationLoggingConfiguration | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| workload | bedrock:DeleteGuardrail | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| breakglass | bedrock:DeleteGuardrail (the AI/ML SCPs have no exemptions) | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| workload | bedrock:ListGuardrails | not denied | not denied | succeeded | pass |
| workload | bedrock:InvokeModel, model off the allow-list | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| workload | bedrock:InvokeModel, allow-listed model | not denied | not denied | succeeded | pass |
| workload | bedrock:InvokeModel, inference profile of an allow-listed model | not denied | not denied | succeeded | pass |
| workload | bedrock:InvokeModel, inference profile of a model off the allow-list | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| workload | sagemaker:CreateNotebookInstance with direct internet access | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| workload | sagemaker:CreateNotebookInstance with root access | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| workload | sagemaker:CreateNotebookInstance without a subnet | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| workload | sagemaker:CreateNotebookInstance without a KMS key | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| workload | sagemaker:CreateNotebookInstance in a VPC, no internet, no root, with a KMS key (subnet does not exist) | not denied | not denied | succeeded | pass |
| workload | sagemaker:UpdateNotebookInstance to root access, on that notebook | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| workload | sagemaker:CreateTrainingJob without a volume KMS key | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| workload | sagemaker:CreateTrainingJob without an output KMS key | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| workload | sagemaker:CreateTrainingJob with both KMS keys | not denied | not denied | ResourceLimitExceeded (reached the service; not denied by policy) | pass |
| iam-user | bedrock:ListFoundationModels | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| iam-user | bedrock:InvokeModel, allow-listed model | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| iam-user | bedrock:ListGuardrails (not a model action) | not denied | not denied | succeeded | pass |
| workload | bedrock:ListFoundationModels | not denied | not denied | succeeded | pass |
| iam-user | ses:GetAccount | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| workload | ses:GetAccount | not denied | not denied | succeeded | pass |
| workload | ram:CreateResourceShare allowing external principals | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |
| workload | ram:CreateResourceShare, organization only | not denied | not denied | succeeded | pass |
| breakglass | ram:CreateResourceShare allowing external principals | not denied | not denied | succeeded | pass |
| workload | ram:AssociateResourceShare to the share that allows external principals | scp | scp | AccessDeniedException: explicit deny in a service control policy | pass |

27/27 probes matched their expectation.

`ResourceLimitExceeded` on the last training job is the account's instance
quota of zero, which SageMaker checks after authorization.

### Identity Center: 6 of 6 read-backs and 4 of 4 probes matched

The permission set was read back from Identity Center, and the role it
provisioned was read back from IAM in the member account:

| Read back | Expected | Result | |
|---|---|---|---|
| Session duration | PT1H | PT1H | pass |
| AWS managed policies | AdministratorAccess | AdministratorAccess | pass |
| Inline policy statement | ProofInlineDeny | ProofInlineDeny | pass |
| Permissions boundary on the permission set | workload-permissions-boundary | workload-permissions-boundary | pass |
| Account assignments | 1 USER | 1 USER | pass |
| Permissions boundary on the role provisioned in the account | arn:aws:iam::111122223333:policy/workload-permissions-boundary | arn:aws:iam::111122223333:policy/workload-permissions-boundary | pass |

| Principal | Request | Expected | Result | Detail | |
|---|---|---|---|---|---|
| sso | s3:ListAllMyBuckets | not denied | not denied | succeeded | pass |
| sso | iam:CreateRole without the boundary | boundary | boundary | AccessDenied: denied by permissions boundary | pass |
| sso | organizations:DescribeOrganization | denied, type not named | denied, type not named | AccessDeniedException: You don't have permissions to access this resource. | pass |
| sso | iam:GetAccountSummary | identity policy | identity policy | AccessDenied: explicit deny in an identity-based policy | pass |

4/4 probes matched their expectation.

The `sso` session has AdministratorAccess, so each denial comes from the
part of the permission set named in the result: the boundary, the inline
policy, or (for Organizations, which does not name it) the boundary again,
as in run 1.

### What this run established about probing these services

The modules needed no changes. Four of the probes did, and the reasons
matter to anyone testing SCPs on these services:

1. **SageMaker resolves the execution role and the KMS key before it checks
   authorization.** A request naming a role or key that does not exist
   fails validation and never reaches the SCP, so it looks allowed. The
   probes create a role with no permissions beyond `kms:DescribeKey` and a
   KMS key, and remove both afterwards.
2. **Some Bedrock models validate the request body before Bedrock checks
   authorization.** An empty body sent to a model off the allow-list
   returned `ValidationException`; a valid request to the same model was
   denied by the SCP. The probes send valid requests of a few tokens, so
   "not denied" means the model answered.
3. **Anthropic models need a use-case form before an account's first
   call**, which stops an allowed request for a reason unrelated to the
   SCP. The proof allow-list uses `amazon.titan*` and `amazon.nova-2-lite*`.
4. **`sagemaker:UpdateNotebookInstance` is only checked against a notebook
   that exists.** The one notebook request the guardrails allow names a
   subnet that does not exist, so it creates a notebook that fails to
   start. That notebook is used for the update probe and then deleted.

The run also confirms two points of design. The AI/ML SCPs exempt nobody:
the break-glass role is denied `bedrock:DeleteGuardrail` like everyone
else. And the model allow-list holds through inference profiles: a profile
of an allow-listed model works, and a profile of any other model is denied
on the underlying foundation-model ARN.

## Not covered by either run

- `organizations:LeaveOrganization`: not probed, because a guardrail bug
  would have acted on the real account. Covered by the offline tests.
- The member account root user: no root credentials were used. Covered by
  the offline tests.
- Bedrock API keys (`bedrock:CallWithBearerToken`), `bedrock:InvokeAgent`
  and `bedrock:CreateModelInvocationJob`: the IAM user was probed with an
  access key on model listing and invocation only.
- `ram:UpdateResourceShare`, and `sagemaker:UpdateNotebookInstance` for
  anything but root access.
- Bedrock invocation logging was not configured in the account, so the
  denied delete had nothing to delete. The denial still came from the SCP.
- `identity-center`: customer managed policy attachments and group
  assignments. The run used an AWS managed policy and a user assignment.
- The other AI/ML modules (the auditors and the logging and cost
  guardrails): not deployed. See [PROOF-AI-ML.md](PROOF-AI-ML.md).
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

Run 2 needs the baseline attached above the sandbox OU, an OU with only
FullAWSAccess attached directly, and a current `aws sso login` for the
assigned user:

```sh
cd proof/run2
cp terraform.tfvars.example terraform.tfvars   # set profiles, the OU, the Identity Center region and user
terraform init && terraform apply
terraform output -json > outputs.json

python probe.py --profile <sandbox-admin> --management-profile <management-admin> --outputs outputs.json

terraform destroy
```

The probe schedules its KMS key for deletion with a seven-day window, so
the key is billed for those days.
