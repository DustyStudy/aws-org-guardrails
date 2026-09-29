# remediate_open_ssh_rdp.py

Shared Lambda source used by both remediation paths in
`auto-remediate-open-ssh-rdp/`:

- **event-driven**: invoked directly by EventBridge with a CloudTrail
  `AuthorizeSecurityGroupIngress` event (revokes only the rule(s) just
  added) or `ModifySecurityGroupRules` event (re-checks the whole group).
- **config-rule**: invoked by an SSM Automation document with
  `{"security_group_id": "sg-xxxxxxxx"}`. Describes the group and revokes
  any matching rule found.

Both trigger types check for TCP rules covering port 22 or 3389 (or any
rule with no port restriction, e.g. protocol `-1`) with `CidrIp: 0.0.0.0/0`
or `CidrIpv6: ::/0`, and revoke only those specific rule entries — other
ingress rules on the same security group are left untouched.

No third-party dependencies; only `boto3` (available in the standard
Lambda Python runtime).
