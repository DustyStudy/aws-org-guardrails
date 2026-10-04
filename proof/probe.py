"""Probe the live guardrails with real API calls and report what denied each one.

Every probe is chosen so that it cannot change anything when the guardrail
works, and changes as little as possible when it does not:

* EC2 calls use DryRun, so an allowed call returns DryRunOperation.
* Other calls target a resource that does not exist (a trail, recorder or
  user named guardrails-probe-*), so an allowed call fails with NotFound.
* The two probes that create an IAM role clean up after themselves.

AWS says which policy type denied a request: other services name it in the
AccessDenied message ("... with an explicit deny in a service control
policy"); EC2 returns an encoded message that sts:DecodeAuthorizationMessage
turns into the matched statement. Each result is classified as scp,
boundary or not-denied, and compared with what the guardrails promise.

Usage:
    python proof/probe.py --profile <sandbox-admin-profile> \\
        --breakglass-role <arn> --app-deployer-role <arn> --boundary-policy <arn>
Writes a Markdown table to stdout with account IDs replaced by 111122223333.
Exits 1 if any probe differs from its expectation.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass

import boto3
from botocore.exceptions import ClientError

SCP = "scp"
BOUNDARY = "boundary"
NOT_DENIED = "not denied"
# Some services (Organizations, for one) deny without naming the policy type.
UNNAMED_DENY = "denied, type not named"
PROBE = "guardrails-probe"

# Statement IDs in the SCP bundles that EC2 requests can match.
SCP_SIDS = {"RequireImdsV2OnLaunch", "DenyImdsDowngrade", "ProtectEbsDefaultEncryption", "DenyOutsideAllowedRegions"}


@dataclass
class Probe:
    principal: str
    description: str
    expected: str
    call: Callable[[boto3.Session], object]
    cleanup: Callable[[boto3.Session], None] | None = None


def classify(session: boto3.Session, fn: Callable[[boto3.Session], object]) -> tuple[str, str]:
    try:
        fn(session)
        return NOT_DENIED, "succeeded"
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message", "")
        if code == "DryRunOperation":
            return NOT_DENIED, "DryRunOperation (would succeed)"
        if "service control policy" in message:
            return SCP, f"{code}: explicit deny in a service control policy"
        if "permissions boundary" in message:
            return BOUNDARY, f"{code}: denied by permissions boundary"
        if code == "UnauthorizedOperation" and "Encoded authorization failure message" in message:
            return decode_ec2(session, message)
        if code in ("AccessDenied", "AccessDeniedException"):
            return UNNAMED_DENY, f"{code}: {message[:120]}"
        return NOT_DENIED, f"{code} (reached the service; not denied by policy)"


def decode_ec2(session: boto3.Session, message: str) -> tuple[str, str]:
    # EC2 hides the reason in an encoded message. The decoded form lists the
    # statements that matched, so a match on one of our SCP Sids identifies it.
    encoded = message.split("Encoded authorization failure message:", 1)[1].strip()
    decoded = json.loads(session.client("sts").decode_authorization_message(EncodedMessage=encoded)["DecodedMessage"])
    sids = sorted({s.get("statementId", "?") for s in decoded.get("matchedStatements", {}).get("items", [])})
    if decoded.get("explicitDeny") and set(sids) & SCP_SIDS:
        return SCP, f"UnauthorizedOperation: SCP statement {', '.join(sids)}"
    return "other deny", f"UnauthorizedOperation: explicitDeny={decoded.get('explicitDeny')} {', '.join(sids)}"


def assume(base: boto3.Session, role_arn: str) -> boto3.Session:
    creds = base.client("sts").assume_role(RoleArn=role_arn, RoleSessionName=PROBE)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name="us-east-1",
    )


def trust_policy(account_id: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                # A bare account ID is the account root in any partition.
                {"Effect": "Allow", "Principal": {"AWS": account_id}, "Action": "sts:AssumeRole"}
            ],
        }
    )


def delete_role_if_exists(name: str) -> Callable[[boto3.Session], None]:
    def cleanup(session: boto3.Session) -> None:
        with contextlib.suppress(ClientError):
            session.client("iam").delete_role(RoleName=name)

    return cleanup


def build_probes(account_id: str, boundary_arn: str, ami: str, instance_id: str | None) -> list[Probe]:
    ec2 = lambda s, region="us-east-1": s.client("ec2", region_name=region)  # noqa: E731

    def run_instances(tokens: str) -> Callable[[boto3.Session], object]:
        return lambda s: ec2(s).run_instances(
            ImageId=ami,
            InstanceType="t3.micro",
            MinCount=1,
            MaxCount=1,
            DryRun=True,
            MetadataOptions={"HttpTokens": tokens},
        )

    probes = [
        # --- SCP: security services (workload = SSO administrator, not exempt)
        Probe("workload", "cloudtrail:StopLogging", SCP, lambda s: s.client("cloudtrail").stop_logging(Name=PROBE)),
        Probe(
            "breakglass",
            "cloudtrail:StopLogging",
            NOT_DENIED,
            lambda s: s.client("cloudtrail").stop_logging(Name=PROBE),
        ),
        Probe(
            "workload",
            "config:StopConfigurationRecorder",
            SCP,
            lambda s: s.client("config").stop_configuration_recorder(ConfigurationRecorderName=PROBE),
        ),
        Probe(
            "breakglass",
            "config:StopConfigurationRecorder",
            NOT_DENIED,
            lambda s: s.client("config").stop_configuration_recorder(ConfigurationRecorderName=PROBE),
        ),
        Probe(
            "workload",
            "guardduty:DeleteDetector",
            SCP,
            lambda s: s.client("guardduty").delete_detector(DetectorId="0" * 32),
        ),
        Probe(
            "workload",
            "access-analyzer:DeleteAnalyzer",
            SCP,
            lambda s: s.client("accessanalyzer").delete_analyzer(analyzerName=PROBE),
        ),
        # --- SCP: identity
        Probe("workload", "iam:CreateAccessKey", SCP, lambda s: s.client("iam").create_access_key(UserName=PROBE)),
        Probe(
            "breakglass",
            "iam:CreateAccessKey",
            NOT_DENIED,
            lambda s: s.client("iam").create_access_key(UserName=PROBE),
        ),
        Probe(
            "workload",
            "iam:CreateRole security-* (exempt-looking name)",
            SCP,
            lambda s: s.client("iam").create_role(
                RoleName=f"security-{PROBE}", AssumeRolePolicyDocument=trust_policy(account_id)
            ),
            cleanup=delete_role_if_exists(f"security-{PROBE}"),
        ),
        Probe(
            "workload",
            "iam:UpdateAssumeRolePolicy on security-breakglass",
            SCP,
            lambda s: s.client("iam").update_assume_role_policy(
                RoleName="security-breakglass", PolicyDocument=trust_policy(account_id)
            ),
        ),
        Probe(
            "workload",
            "account:EnableRegion",
            SCP,
            lambda s: s.client("account").enable_region(RegionName="xx-probe-1"),
        ),
        # --- SCP: data and compute
        Probe("workload", "ec2:RunInstances without IMDSv2", SCP, run_instances("optional")),
        Probe("workload", "ec2:RunInstances with IMDSv2", NOT_DENIED, run_instances("required")),
        Probe(
            "workload",
            "ec2:DisableEbsEncryptionByDefault",
            SCP,
            lambda s: ec2(s).disable_ebs_encryption_by_default(DryRun=True),
        ),
        Probe(
            "breakglass",
            "ec2:DisableEbsEncryptionByDefault",
            NOT_DENIED,
            lambda s: ec2(s).disable_ebs_encryption_by_default(DryRun=True),
        ),
        Probe(
            "workload",
            "s3:PutAccountPublicAccessBlock",
            SCP,
            lambda s: s.client("s3control").put_public_access_block(
                AccountId=account_id,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
            ),
        ),
        # --- SCP: regions
        Probe("workload", "ec2:DescribeInstances in us-east-1", NOT_DENIED, lambda s: ec2(s).describe_instances()),
        Probe(
            "workload",
            "ec2:DescribeInstances in us-east-2",
            NOT_DENIED,
            lambda s: ec2(s, "us-east-2").describe_instances(),
        ),
        Probe(
            "workload", "ec2:DescribeInstances in eu-west-1", SCP, lambda s: ec2(s, "eu-west-1").describe_instances()
        ),
        Probe(
            "workload",
            "iam:ListRoles via eu-west-1 (global service)",
            NOT_DENIED,
            lambda s: s.client("iam", region_name="eu-west-1").list_roles(MaxItems=1),
        ),
        Probe(
            "breakglass",
            "ec2:DescribeInstances in eu-west-1",
            NOT_DENIED,
            lambda s: ec2(s, "eu-west-1").describe_instances(),
        ),
        # --- Permissions boundary (app-deployer: AdministratorAccess + boundary)
        Probe(
            "app-deployer",
            "iam:CreateRole under /workload/ with the boundary",
            NOT_DENIED,
            lambda s: s.client("iam").create_role(
                RoleName=f"{PROBE}-ok",
                Path="/workload/",
                AssumeRolePolicyDocument=trust_policy(account_id),
                PermissionsBoundary=boundary_arn,
            ),
            cleanup=delete_role_if_exists(f"{PROBE}-ok"),
        ),
        Probe(
            "app-deployer",
            "iam:CreateRole without the boundary",
            BOUNDARY,
            lambda s: s.client("iam").create_role(
                RoleName=f"{PROBE}-nob", Path="/workload/", AssumeRolePolicyDocument=trust_policy(account_id)
            ),
            cleanup=delete_role_if_exists(f"{PROBE}-nob"),
        ),
        Probe(
            "app-deployer",
            "iam:CreateRole outside /workload/",
            BOUNDARY,
            lambda s: s.client("iam").create_role(
                RoleName=f"{PROBE}-path",
                AssumeRolePolicyDocument=trust_policy(account_id),
                PermissionsBoundary=boundary_arn,
            ),
            cleanup=delete_role_if_exists(f"{PROBE}-path"),
        ),
        Probe(
            "app-deployer",
            "iam:DeleteRolePermissionsBoundary on itself",
            BOUNDARY,
            lambda s: s.client("iam").delete_role_permissions_boundary(RoleName="app-deployer"),
        ),
        Probe(
            "app-deployer",
            "iam:CreatePolicyVersion on the boundary policy",
            BOUNDARY,
            lambda s: s.client("iam").create_policy_version(
                PolicyArn=boundary_arn,
                PolicyDocument=json.dumps(
                    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
                ),
            ),
        ),
        Probe(
            "app-deployer",
            "organizations:DescribeOrganization",
            UNNAMED_DENY,
            lambda s: s.client("organizations").describe_organization(),
        ),
        Probe(
            "workload",
            "organizations:DescribeOrganization",
            NOT_DENIED,
            lambda s: s.client("organizations").describe_organization(),
        ),
        Probe("app-deployer", "s3:ListAllMyBuckets", NOT_DENIED, lambda s: s.client("s3").list_buckets()),
    ]
    if instance_id:
        # EC2 checks that the instance exists before it checks authorization,
        # so this rule can only be probed against a real instance.
        def downgrade(s: boto3.Session) -> object:
            return ec2(s).modify_instance_metadata_options(InstanceId=instance_id, HttpTokens="optional", DryRun=True)

        probes += [
            Probe("workload", "ec2:ModifyInstanceMetadataOptions (IMDSv1 downgrade)", SCP, downgrade),
            Probe("breakglass", "ec2:ModifyInstanceMetadataOptions (IMDSv1 downgrade)", NOT_DENIED, downgrade),
        ]
    return probes


def launch_instance(session: boto3.Session, ami: str) -> str:
    """Launch the smallest instance with IMDSv2 required (itself a guardrail probe)."""
    client = session.client("ec2")
    reservation = client.run_instances(
        ImageId=ami,
        InstanceType="t3.nano",
        MinCount=1,
        MaxCount=1,
        MetadataOptions={"HttpTokens": "required"},
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": PROBE}]}],
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    client.get_waiter("instance_exists").wait(InstanceIds=[instance_id])
    return instance_id


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--profile", required=True)
    parser.add_argument("--breakglass-role", required=True)
    parser.add_argument("--app-deployer-role", required=True)
    parser.add_argument("--boundary-policy", required=True)
    parser.add_argument(
        "--launch-instance",
        action="store_true",
        help="launch a t3.nano (IMDSv2) to probe ModifyInstanceMetadataOptions, then terminate it",
    )
    args = parser.parse_args()

    base = boto3.Session(profile_name=args.profile, region_name="us-east-1")
    account_id = base.client("sts").get_caller_identity()["Account"]
    ami = base.client("ssm").get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    sessions = {
        "workload": base,
        "breakglass": assume(base, args.breakglass_role),
        "app-deployer": assume(base, args.app_deployer_role),
    }

    instance_id = launch_instance(base, ami) if args.launch_instance else None
    rows, failures = [], 0
    try:
        for probe in build_probes(account_id, args.boundary_policy, ami, instance_id):
            session = sessions[probe.principal]
            actual, detail = classify(session, probe.call)
            if probe.cleanup:
                probe.cleanup(sessions["breakglass"])
            ok = actual == probe.expected
            failures += not ok
            rows.append(
                (probe.principal, probe.description, probe.expected, actual, detail, "pass" if ok else "**FAIL**")
            )
    finally:
        if instance_id:
            base.client("ec2").terminate_instances(InstanceIds=[instance_id])
            print(f"terminated probe instance {instance_id[:5]}...", file=sys.stderr)

    print("| Principal | Request | Expected | Result | Detail | |")
    print("|---|---|---|---|---|---|")
    for row in rows:
        line = "| " + " | ".join(row) + " |"
        print(re.sub(r"\b\d{12}\b", "111122223333", line))
    print(f"\n{len(rows) - failures}/{len(rows)} probes matched their expectation.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
