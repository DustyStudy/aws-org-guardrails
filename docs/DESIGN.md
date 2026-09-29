# Design notes

Why the modules are built the way they are, and what was traded away.

## Policies are rendered with `jsonencode`, not `aws_iam_policy_document`

`aws_iam_policy_document` is a data source, so it belongs to the AWS
provider. With a mocked provider in `terraform test` it returns placeholder
JSON, and outside tests it needs provider configuration just to build a
string. Writing the policies as HCL objects passed to `jsonencode` keeps the
`policies` module provider-free:

- `terraform plan` renders the real JSON offline, which the Python tests read.
- The other modules can be tested with a mocked provider and still assert on
  real policy content.
- `jsonencode` output is minified, which matters for the SCP size limit below.

The cost is losing the data source's statement merging and its validation of
element names. The evaluator raises on unknown statement elements, which
covers the second point.

## Four bundles, not one SCP per control

AWS allows 5 SCPs attached directly to a root, OU or account, and each SCP is
limited to 5,120 characters. FullAWSAccess normally takes one slot. One SCP
per control would hit the count limit almost immediately. One big SCP would
be hard to review and would eventually hit the size limit.

Four bundles grouped by what they protect leave a slot free.
`tests/test_scps.py` checks both limits on every render, and the
`scp-baseline` module refuses to plan an attachment that would exceed 5 once
`other_scps_per_target` is counted.

## Exempt principals are required

Almost every Deny carries `ArnNotLike aws:PrincipalArn [exempt roles]`. The
modules refuse an empty list. Without an exemption, nobody could fix a broken
CloudTrail trail or roll GuardDuty settings forward without first detaching
the SCP from the whole OU, which is exactly the change window an attacker
would want.

Three statements have no exemption on purpose:

- `DenyLeaveOrganization`: no principal in a member account needs this.
- `DenyRootUser`: root in member accounts is handled from the management
  account (centralized root access), not from inside the account.
- `RequireImdsV2OnLaunch`: it has no legitimate exception.

A test asserts that exactly these statements lack the exemption, so adding a
new statement without one fails CI until it is added to the list on purpose.

## The IMDSv2 rule is scoped to the instance resource

`ec2:RunInstances` is authorized once per resource it touches: the instance,
but also the AMI, subnet, security group, volume and network interface. Only
the instance request carries `ec2:MetadataHttpTokens`. With `Resource: "*"`,
`StringNotEquals` on a missing key evaluates to true and the deny would block
every launch. The mutation check below confirms the tests catch that.

A launch request with no metadata option is denied too, because
`StringNotEquals` is true when the key is missing. Callers must ask for IMDSv2
explicitly. Check how your launch tooling (launch templates, Auto Scaling,
Terraform) sets the option before attaching this bundle to a production OU.

## Region restriction uses `NotAction` with a global-service list

Global services (IAM, Organizations, STS, Route 53, CloudFront, Support,
billing) are served from one region. A region deny without a carve-out
breaks them for anyone whose SDK points elsewhere. The carve-out list is kept
short and reviewable. The tests assert both sides: `ec2:RunInstances` in
`eu-west-1` is denied, while `iam:CreateRole` and `sts:AssumeRole` from
`eu-west-1` are allowed.

IAM Identity Center is regional. If its home region is not in
`allowed_regions`, add it, or administrators will be denied.

## CloudTrail and Config protections apply to every trail and recorder

The audit-logging statement uses `Resource: "*"`, so it also covers trails
that application teams create themselves. Scoping it to the organization
trail ARN would let teams manage their own trails. The trade-off chosen here
is that nothing but the security pipeline changes logging configuration. An
organization that wants team-owned trails should scope the CloudTrail
actions to the org trail ARN.

## The boundary allows `*` and removes escalation paths

A permissions boundary is a ceiling, not a grant. `Allow *` in the boundary
grants nothing by itself: a principal still needs an identity policy. The
Deny statements close the known ways to climb out of the ceiling:

1. creating a role or user without the same boundary,
2. removing the boundary,
3. editing the boundary policy (new version or default version change),
4. changing or passing roles outside the delegated path,
5. touching Organizations or account settings.

The alternative, a boundary that lists allowed services, is stricter but has
to be updated every time a team adopts a new service. It also tends to grow
until it is effectively `*` anyway.

Checkov cannot see the rendered boundary (the JSON comes from a module
output), so no Checkov skips are needed or present. The behavior tests carry
that coverage instead.

## Identity Center: boundary required by default

The `identity-center` module refuses to plan a permission set with no
boundary unless its name is in `boundary_exempt_permission_sets`. The
exemption list makes a break-glass administrator possible and makes it
visible in code review. Sessions default to one hour and are capped at
twelve, the maximum Identity Center allows.

Account assignments depend on every policy and boundary attachment, so the
first sign-in with a new permission set never runs without them.

## How the tests were checked

A test suite that never fails proves little, so each of these deliberate
bugs was introduced into the policies and the suite was run against it:

| Mutation | Caught? |
|----------|:---:|
| Exemption condition changed from `ArnNotLike` to `ArnLike` | Yes |
| IMDSv2 rule widened from `instance/*` to `*` | Yes |
| `iam:*` removed from the global-service carve-out | Yes |
| Root-user ARN hard-coded to `arn:aws:` | Yes (GovCloud test) |
| Delegated path `NotResource` changed to `Resource` | Yes |
| `StringNotEquals` changed to `StringNotLike` on the boundary check | No, and correctly so: without wildcards the two are equivalent |

## Roadmap

- **Resource control policies (RCPs):** a data-perimeter bundle (deny access
  from outside the organization to S3, KMS, STS and Secrets Manager).
- **Declarative policies for EC2:** enforce the IMDS default and block public
  AMI sharing at the service level rather than per API call.
- **Access Analyzer in CI:** run `scripts/validate_policies.py` from a
  read-only OIDC role on every pull request.
- **Live verification:** attach the bundles to a sandbox OU and record the
  results the way the remediation and evidence projects do.
