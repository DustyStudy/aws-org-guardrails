# policies

Renders the SCP bundles and the permissions boundary as JSON. It has no
provider and creates no resources, so `terraform plan` renders the real
policy text offline. The other modules call it, and the Python tests read its
output to evaluate the policies.

## Inputs

| Name | Default | Description |
|------|---------|-------------|
| `partition` | `"aws"` | `aws`, `aws-us-gov` or `aws-cn`. Every ARN in the output uses it. |
| `exempt_principal_arns` | `null` | Role ARN patterns the SCPs do not apply to. Required for SCPs; with `null` only the boundary renders. |
| `allowed_regions` | `["us-east-1", "us-west-2"]` | Regions workloads may use. Must match the partition. |
| `enable_region_restriction` | `true` | Render the `region-restriction` bundle. |
| `deny_iam_user_credentials` | `true` | Deny IAM users, access keys and console passwords. |
| `deny_service_specific_credentials` | `false` | Deny creating or resetting service-specific credentials (Bedrock API keys, CodeCommit Git credentials, Keyspaces passwords) outside exempt roles. Breaks pipelines that issue them from other roles. |
| `require_imds_hop_limit_one` | `false` | Deny launching an instance unless its IMDS hop limit is 1, so bridge-networked containers on it cannot fetch the instance role's credentials. Host-networked containers still can. Launches that leave the hop limit unset are denied too. Breaks pipelines and node provisioners such as Karpenter that launch with a hop limit of 2 from a non-exempt role. Auto Scaling and EKS managed node groups launch through service-linked roles, which SCPs do not restrict, so those launches are neither broken nor covered. |
| `deny_athena_results_bucket_outside_org` | `false` | Deny object reads and writes, `ListBucket` and `GetBucketLocation` on buckets named `aws-athena-query-results-<account-id>-<region>` owned outside the organization (Athena result bucket sniping, CVE-2026-118029). Buckets in standalone accounts are denied too. Breaks only workloads that use such a bucket in an outside account. No exemption. |
| `deny_tagged_kms_keys_off_org_network` | `false` | Deny signing, decrypting, grants, key-policy and tag changes on KMS keys tagged `guardrails:network-perimeter=true` unless the call comes through a VPC endpoint owned by the organization (stolen laptop credentials, Binance 2026). AWS service calls on the caller's behalf are skipped (so SSE-KMS reads through S3 are not covered), existing replicas must be tagged too; exempt roles keep access. Breaks any caller of a tagged key that reaches KMS over the public endpoint, including people using the console or CLI from a laptop. |
| `deny_ses_to_iam_users` | `false` | Deny every SES action to IAM users (leaked keys used for SES and SMTP abuse). Breaks SES SMTP senders that are not exempted. |
| `ses_iam_user_exempt_principal_arns` | `[]` | IAM user ARN patterns that keep SES, such as `arn:aws:iam::*:user/ses-smtp-*`. |
| `third_party_vendor_networks` | `{}` | Per outside vendor, the role or user ARN patterns its credentials belong to (`principal_arns`) and the source CIDRs it publishes (`source_cidrs`). Each entry adds a core statement denying those principals access from any other address, so a credential stolen from the vendor (Fireworks AI, 2026) fails from the attacker's network. AWS service calls on the caller's behalf are skipped; exempt roles are unaffected. Breaks the vendor if its egress ranges change or it reaches AWS through a VPC endpoint, and does not stop an attacker running code on the vendor's own machines. List roles the vendor chains into too: their sessions carry their own ARN. |
| `protected_role_name_prefixes` | `["OrganizationAccountAccessRole", "security-"]` | Roles only exempt principals may change. |
| `boundary_policy_name` | `"workload-permissions-boundary"` | Boundary policy name the boundary refers to itself by. |
| `boundary_policy_path` | `"/"` | Boundary policy path. |
| `delegated_role_path` | `"/workload/"` | Path where bounded principals may manage and pass roles. |
| `service_linked_role_services` | ECS, EKS, ELB, RDS, Auto Scaling and others | Services whose service-linked roles bounded principals may create. |

## Outputs

| Name | Description |
|------|-------------|
| `scp_policies` | Map of bundle name to minified SCP JSON. |
| `permissions_boundary_policy` | Boundary policy JSON. |
| `boundary_policy_arn_template` | Boundary ARN with `${aws:PrincipalAccount}` in place of the account ID. |
