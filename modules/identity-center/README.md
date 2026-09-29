# identity-center

IAM Identity Center permission sets with AWS managed policies, customer
managed policies, an inline policy and a permissions boundary, plus account
assignments for groups or users.

By default every permission set must have a boundary. A set without one
(a break-glass administrator, for example) must be named in
`boundary_exempt_permission_sets`, which keeps the exception visible in code
review.

## Inputs

| Name | Default | Description |
|------|---------|-------------|
| `instance_arn` | (required) | Identity Center instance ARN. |
| `permission_sets` | (required) | Map of name to `{ description, session_duration, relay_state, managed_policy_arns, customer_managed_policies, inline_policy, permissions_boundary }`. Sessions default to `PT1H`, maximum `PT12H`. |
| `require_permissions_boundary` | `true` | Fail the plan for a permission set without a boundary. |
| `boundary_exempt_permission_sets` | `[]` | Names allowed to have no boundary. |
| `account_assignments` | `[]` | List of `{ permission_set, principal_type, principal_id, account_id }`. `principal_type` defaults to `GROUP`. |
| `tags` | `{}` | Tags for every permission set. |

## Outputs

`permission_set_arns` (map of name to ARN) and `account_assignments`.
