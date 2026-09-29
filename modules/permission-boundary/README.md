# permission-boundary

Creates the permissions boundary policy in the account its provider points
at. Deploy it to every account where delegated principals or bounded
Identity Center permission sets are used; Identity Center resolves a
customer managed boundary by name in each account.

The policy refers to itself as
`arn:<partition>:iam::${aws:PrincipalAccount}:policy<path><name>`, so the name
and path must be the same in every account.

## Inputs

| Name | Default | Description |
|------|---------|-------------|
| `policy_name` | `"workload-permissions-boundary"` | Policy name. |
| `policy_path` | `"/"` | Policy path. |
| `delegated_role_path` | `"/workload/"` | Path where bounded principals may create, change and pass roles. |
| `tags` | `{}` | Tags for the policy. |

## Outputs

`policy_arn`, `policy_name`, `policy_path`.
