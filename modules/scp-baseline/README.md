# scp-baseline

Creates the SCP bundles from the [`policies`](../policies) module and
attaches each enabled bundle to every target. Run it from the management
account or an account delegated for Organizations policy management.

The partition comes from the provider, so the same call works in GovCloud.

## Inputs

| Name | Default | Description |
|------|---------|-------------|
| `target_ids` | (required) | Root, OU or account IDs to attach the bundles to. |
| `exempt_principal_arns` | (required) | Break-glass and security pipeline role ARN patterns. At least one. |
| `enabled_bundles` | all | Subset of `core`, `security-services`, `data-and-compute`, `region-restriction`. |
| `other_scps_per_target` | `1` | SCPs already attached to each target (FullAWSAccess counts). The plan fails if the total would exceed 5. |
| `allowed_regions` | `["us-east-1", "us-west-2"]` | Passed to `policies`. |
| `enable_region_restriction` | `true` | Passed to `policies`. |
| `deny_iam_user_credentials` | `true` | Passed to `policies`. |
| `protected_role_name_prefixes` | see `policies` | Passed to `policies`. |
| `name_prefix` | `"guardrails"` | SCP names are `<name_prefix>-<bundle>`. |
| `tags` | `{}` | Tags for every SCP. |

## Outputs

`policy_ids`, `policy_arns` (maps keyed by bundle) and `attachments`
(`bundle/target` keys).
