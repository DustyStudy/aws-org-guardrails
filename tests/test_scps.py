"""Behavior tests for the rendered SCP bundles.

Each test states a request a real principal would make and the outcome the
guardrails promise, then evaluates it against the JSON Terraform rendered.
"""

import pytest

from guardrails_tools.iam_eval import Decision, Request, scp_decision

ACCOUNT = "111122223333"
WORKLOAD = f"arn:aws:iam::{ACCOUNT}:role/app-deployer"
BREAKGLASS = f"arn:aws:iam::{ACCOUNT}:role/security-breakglass"
PIPELINE = f"arn:aws:iam::{ACCOUNT}:role/security-pipeline"
ROOT = f"arn:aws:iam::{ACCOUNT}:root"

# AWS limits (Organizations quotas): characters per SCP, and SCPs attached
# directly to one target. One of those slots normally holds FullAWSAccess.
SCP_MAX_CHARS = 5120
SCP_MAX_PER_TARGET = 5

# Statements that apply to everyone, exempt principals included.
NO_EXEMPTION = {"DenyLeaveOrganization", "DenyRootUser", "RequireImdsV2OnLaunch"}


def req(action, principal=WORKLOAD, resource="*", region="us-east-1", **extra):
    return Request(
        action,
        resource,
        {"aws:PrincipalArn": principal, "aws:RequestedRegion": region, "aws:PrincipalAccount": ACCOUNT, **extra},
    )


def decide(rendered, request):
    return scp_decision(rendered.scps.values(), request)


# --- limits and structure -------------------------------------------------


def test_every_bundle_fits_the_scp_size_limit(commercial, govcloud):
    for rendered in (commercial, govcloud):
        for name, raw in rendered.scps_raw.items():
            assert len(raw) <= SCP_MAX_CHARS, f"{name} is {len(raw)} characters"


def test_bundles_leave_a_slot_for_full_aws_access(commercial):
    assert len(commercial.scps) <= SCP_MAX_PER_TARGET - 1


def test_scps_only_deny(commercial):
    for name, doc in commercial.scps.items():
        for statement in doc["Statement"]:
            assert statement["Effect"] == "Deny", f"{name}/{statement['Sid']} grants access"


def test_sids_are_unique_across_bundles(commercial):
    sids = [s["Sid"] for doc in commercial.scps.values() for s in doc["Statement"]]
    assert len(sids) == len(set(sids))


def test_exemption_is_on_every_statement_that_should_have_it(commercial):
    for doc in commercial.scps.values():
        for statement in doc["Statement"]:
            has_exemption = "aws:PrincipalArn" in statement.get("Condition", {}).get("ArnNotLike", {})
            assert has_exemption is (statement["Sid"] not in NO_EXEMPTION), statement["Sid"]


# --- organization and identity ---------------------------------------------


@pytest.mark.parametrize("principal", [WORKLOAD, BREAKGLASS])
def test_nobody_in_a_member_account_can_leave_the_organization(commercial, principal):
    assert decide(commercial, req("organizations:LeaveOrganization", principal)) is Decision.EXPLICIT_DENY


@pytest.mark.parametrize("action", ["s3:ListAllMyBuckets", "iam:CreateAccessKey", "ec2:DescribeInstances"])
def test_member_account_root_user_is_denied_everything(commercial, action):
    assert decide(commercial, req(action, ROOT)) is Decision.EXPLICIT_DENY


def test_root_deny_is_partition_specific(govcloud):
    # A GovCloud render must match GovCloud ARNs. A hard-coded arn:aws: would
    # silently never match there, which is the bug this test exists to catch.
    gov_root = f"arn:aws-us-gov:iam::{ACCOUNT}:root"
    assert decide(govcloud, req("s3:ListAllMyBuckets", gov_root, region="us-gov-west-1")) is Decision.EXPLICIT_DENY


@pytest.mark.parametrize("action", ["iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile"])
def test_long_lived_iam_user_credentials_are_denied(commercial, action):
    assert decide(commercial, req(action)) is Decision.EXPLICIT_DENY
    assert decide(commercial, req(action, BREAKGLASS)) is Decision.ALLOW


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        ("OrganizationAccountAccessRole", Decision.EXPLICIT_DENY),
        ("security-audit-readonly", Decision.EXPLICIT_DENY),
        ("app-deployer", Decision.ALLOW),
    ],
)
def test_protected_roles_cannot_be_changed_by_workloads(commercial, role, expected):
    arn = f"arn:aws:iam::{ACCOUNT}:role/{role}"
    for action in ("iam:DeleteRole", "iam:AttachRolePolicy", "iam:UpdateAssumeRolePolicy"):
        assert decide(commercial, req(action, resource=arn)) is expected


def test_pipeline_can_maintain_protected_roles(commercial):
    arn = f"arn:aws:iam::{ACCOUNT}:role/OrganizationAccountAccessRole"
    assert decide(commercial, req("iam:UpdateAssumeRolePolicy", PIPELINE, arn)) is Decision.ALLOW


# --- security services ------------------------------------------------------


@pytest.mark.parametrize(
    "action",
    [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "config:StopConfigurationRecorder",
        "guardduty:DeleteDetector",
        "guardduty:CreateFilter",
        "securityhub:DisableSecurityHub",
        "access-analyzer:DeleteAnalyzer",
    ],
)
def test_workloads_cannot_blind_security_tooling(commercial, action):
    assert decide(commercial, req(action)) is Decision.EXPLICIT_DENY
    assert decide(commercial, req(action, PIPELINE)) is Decision.ALLOW


@pytest.mark.parametrize("action", ["cloudtrail:LookupEvents", "guardduty:ListFindings", "securityhub:GetFindings"])
def test_reading_security_findings_is_not_blocked(commercial, action):
    assert decide(commercial, req(action)) is Decision.ALLOW


# --- data and compute --------------------------------------------------------


def test_instances_must_launch_with_imdsv2(commercial):
    instance = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/*"
    optional = req("ec2:RunInstances", resource=instance, **{"ec2:MetadataHttpTokens": "optional"})
    required = req("ec2:RunInstances", resource=instance, **{"ec2:MetadataHttpTokens": "required"})
    unspecified = req("ec2:RunInstances", resource=instance)
    assert decide(commercial, optional) is Decision.EXPLICIT_DENY
    assert decide(commercial, required) is Decision.ALLOW
    # Leaving the setting out is denied too: the caller must ask for IMDSv2.
    assert decide(commercial, unspecified) is Decision.EXPLICIT_DENY


def test_imds_rule_only_applies_to_the_instance_resource(commercial):
    # RunInstances is also authorized against the subnet, AMI, volume and so
    # on. Those requests never carry ec2:MetadataHttpTokens and must pass.
    subnet = f"arn:aws:ec2:us-east-1:{ACCOUNT}:subnet/subnet-0abc"
    assert decide(commercial, req("ec2:RunInstances", resource=subnet)) is Decision.ALLOW


@pytest.mark.parametrize(
    "action",
    ["ec2:DisableEbsEncryptionByDefault", "s3:PutAccountPublicAccessBlock", "ec2:ModifyInstanceMetadataOptions"],
)
def test_account_level_data_protections_are_locked(commercial, action):
    assert decide(commercial, req(action)) is Decision.EXPLICIT_DENY
    assert decide(commercial, req(action, BREAKGLASS)) is Decision.ALLOW


# --- regions ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("action", "region", "expected"),
    [
        ("ec2:RunInstances", "us-east-1", Decision.ALLOW),
        ("ec2:RunInstances", "eu-west-1", Decision.EXPLICIT_DENY),
        ("s3:CreateBucket", "ap-southeast-2", Decision.EXPLICIT_DENY),
        # Global services are served from us-east-1 but must keep working
        # whatever region the caller's SDK is configured for.
        ("iam:CreateRole", "eu-west-1", Decision.ALLOW),
        ("sts:AssumeRole", "eu-west-1", Decision.ALLOW),
        ("support:CreateCase", "eu-west-1", Decision.ALLOW),
    ],
)
def test_region_restriction(commercial, action, region, expected):
    assert decide(commercial, req(action, region=region)) is expected


def test_breakglass_can_work_in_any_region(commercial):
    assert decide(commercial, req("ec2:RunInstances", BREAKGLASS, region="eu-west-1")) is Decision.ALLOW


def test_govcloud_render_allows_only_govcloud_regions(govcloud):
    principal = f"arn:aws-us-gov:iam::{ACCOUNT}:role/app-deployer"
    assert decide(govcloud, req("ec2:RunInstances", principal, region="us-gov-west-1")) is Decision.ALLOW
    assert decide(govcloud, req("ec2:RunInstances", principal, region="us-east-1")) is Decision.EXPLICIT_DENY
