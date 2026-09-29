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
| `protected_role_name_prefixes` | `["OrganizationAccountAccessRole", "security-"]` | Roles only exempt principals may change. |
| `boundary_policy_name` | `"workload-permissions-boundary"` | Boundary policy name the boundary refers to itself by. |
| `boundary_policy_path` | `"/"` | Boundary policy path. |
| `delegated_role_path` | `"/workload/"` | Path where bounded principals may manage and pass roles. |

## Outputs

| Name | Description |
|------|-------------|
| `scp_policies` | Map of bundle name to minified SCP JSON. |
| `permissions_boundary_policy` | Boundary policy JSON. |
| `boundary_policy_arn_template` | Boundary ARN with `${aws:PrincipalAccount}` in place of the account ID. |
