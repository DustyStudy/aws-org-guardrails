"""Behavior tests for the rendered SCP bundles.

Each test states a request a real principal would make and the outcome the
guardrails promise, then evaluates it against the JSON Terraform rendered.
"""

import pytest

from guardrails_tools.iam_eval import Decision, Request, glob_match, scp_decision

ACCOUNT = "111122223333"
WORKLOAD = f"arn:aws:iam::{ACCOUNT}:role/app-deployer"
BREAKGLASS = f"arn:aws:iam::{ACCOUNT}:role/security-breakglass"
PIPELINE = f"arn:aws:iam::{ACCOUNT}:role/security-pipeline"
ROOT = f"arn:aws:iam::{ACCOUNT}:root"

# The pre-May-2026 AWS limits (characters per SCP, SCPs attached directly to
# one target), kept on purpose as a compatibility margin. One slot
# normally holds FullAWSAccess.
SCP_MAX_CHARS = 5120
SCP_MAX_PER_TARGET = 5

# Statements that apply to everyone, exempt principals included.
NO_EXEMPTION = {"DenyLeaveOrganization", "DenyRootUser", "RequireImdsV2OnLaunch", "DenyAthenaResultsBucketOutsideOrg"}


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


def test_exemption_is_on_every_statement_that_should_have_it(commercial, data_locked):
    for doc in [*commercial.scps.values(), *data_locked.scps.values()]:
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


def test_centralized_root_access_sessions_are_not_denied(commercial):
    # sts:AssumeRoot sessions carry the root ARN plus aws:AssumedRoot.
    request = req("s3:DeleteBucketPolicy", ROOT, **{"aws:AssumedRoot": "true"})
    assert decide(commercial, request) is Decision.ALLOW


def test_protected_customer_managed_policies_cannot_be_rewritten(commercial):
    for policy in (
        f"arn:aws:iam::{ACCOUNT}:policy/security-breakglass-admin",
        f"arn:aws:iam::{ACCOUNT}:policy/platform/security-breakglass-admin",
    ):
        for action in ("iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"):
            assert decide(commercial, req(action, WORKLOAD, resource=policy)) is Decision.EXPLICIT_DENY
            assert decide(commercial, req(action, BREAKGLASS, resource=policy)) is Decision.ALLOW
    app_policy = f"arn:aws:iam::{ACCOUNT}:policy/workload/app-policy"
    assert decide(commercial, req("iam:CreatePolicyVersion", WORKLOAD, resource=app_policy)) is Decision.ALLOW


def test_root_deny_is_partition_specific(govcloud):
    # A GovCloud render must match GovCloud ARNs. A hard-coded arn:aws: would
    # silently never match there, which is the bug this test exists to catch.
    gov_root = f"arn:aws-us-gov:iam::{ACCOUNT}:root"
    assert decide(govcloud, req("s3:ListAllMyBuckets", gov_root, region="us-gov-west-1")) is Decision.EXPLICIT_DENY


@pytest.mark.parametrize("action", ["iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile"])
def test_long_lived_iam_user_credentials_are_denied(commercial, action):
    assert decide(commercial, req(action)) is Decision.EXPLICIT_DENY
    assert decide(commercial, req(action, BREAKGLASS)) is Decision.ALLOW


SSC_MINT = ["iam:CreateServiceSpecificCredential", "iam:ResetServiceSpecificCredential"]


def test_service_specific_credentials_stay_open_by_default(commercial):
    assert "DenyServiceSpecificCredentials" not in commercial.scps_raw["core"]


@pytest.mark.parametrize("action", SSC_MINT)
def test_bedrock_api_keys_and_git_credentials_cannot_be_minted(ssc_locked, action):
    assert decide(ssc_locked, req(action)) is Decision.EXPLICIT_DENY
    assert decide(ssc_locked, req(action, BREAKGLASS)) is Decision.ALLOW


def test_service_specific_credentials_can_still_be_deactivated(ssc_locked):
    # Responders outside the exempt roles must still be able to switch one off.
    assert decide(ssc_locked, req("iam:UpdateServiceSpecificCredential")) is Decision.ALLOW
    assert decide(ssc_locked, req("iam:DeleteServiceSpecificCredential")) is Decision.ALLOW


def test_core_bundle_with_service_specific_credential_deny_fits_the_scp_size_limit(ssc_locked):
    assert len(ssc_locked.scps_raw["core"]) <= SCP_MAX_CHARS


IAM_USER = f"arn:aws:iam::{ACCOUNT}:user/wordpress-uploads"
SMTP_USER = f"arn:aws:iam::{ACCOUNT}:user/ses-smtp-billing"
SES_ABUSE = ["ses:SendRawEmail", "ses:GetSendQuota", "ses:CreateEmailIdentity", "ses:PutAccountDetails"]


def test_ses_stays_open_to_iam_users_by_default(commercial):
    # Off by default: SES SMTP senders are IAM users and would stop sending.
    assert "DenySesToIamUsers" not in commercial.scps_raw["core"]


@pytest.mark.parametrize("action", SES_ABUSE)
def test_leaked_iam_user_key_cannot_use_ses(ses_locked, action):
    request = req(action, IAM_USER, **{"aws:PrincipalType": "User"})
    assert decide(ses_locked, request) is Decision.EXPLICIT_DENY


def test_listed_smtp_user_and_roles_keep_ses(ses_locked):
    smtp = req("ses:SendRawEmail", SMTP_USER, **{"aws:PrincipalType": "User"})
    role = req("ses:SendEmail", WORKLOAD, **{"aws:PrincipalType": "AssumedRole"})
    assert decide(ses_locked, smtp) is Decision.ALLOW
    assert decide(ses_locked, role) is Decision.ALLOW


def test_ses_deny_leaves_other_services_to_iam_users(ses_locked):
    request = req("s3:GetObject", IAM_USER, **{"aws:PrincipalType": "User"})
    assert decide(ses_locked, request) is Decision.ALLOW


def test_core_bundle_with_ses_deny_fits_the_scp_size_limit(ses_locked):
    assert len(ses_locked.scps_raw["core"]) <= SCP_MAX_CHARS


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
    for action in ("iam:DeleteRole", "iam:AttachRolePolicy", "iam:UpdateAssumeRolePolicy", "iam:PassRole"):
        assert decide(commercial, req(action, resource=arn)) is expected


def test_exempt_roles_cannot_be_passed_to_compute(commercial):
    # A function or instance running as an exempt role would inherit its exemption.
    arn = f"arn:aws:iam::{ACCOUNT}:role/security-breakglass"
    assert decide(commercial, req("iam:PassRole", resource=arn)) is Decision.EXPLICIT_DENY
    assert decide(commercial, req("iam:PassRole", PIPELINE, arn)) is Decision.ALLOW


def test_nobody_can_create_a_role_named_like_an_exempt_principal(commercial):
    # Otherwise any admin in a member account could create "security-breakglass"
    # and inherit the exemption from every guardrail.
    for name in ("security-breakglass", "security-pipeline"):
        arn = f"arn:aws:iam::{ACCOUNT}:role/{name}"
        assert decide(commercial, req("iam:CreateRole", resource=arn)) is Decision.EXPLICIT_DENY


def test_every_exempt_role_is_protected(commercial):
    core = commercial.scps["core"]["Statement"]
    protected = next(s for s in core if s["Sid"] == "DenyProtectedRoleChanges")
    exempt = protected["Condition"]["ArnNotLike"]["aws:PrincipalArn"]
    for pattern in exempt:
        name = pattern.split(":role/", 1)[1]
        assert any(glob_match(res.split(":role/", 1)[1], name) for res in protected["Resource"]), pattern


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
        # CloudTrail Lake, aggregators and the administrator's member list.
        "cloudtrail:StopEventDataStoreIngestion",
        "cloudtrail:DeleteEventDataStore",
        "config:DeleteConfigurationAggregator",
        "guardduty:DisassociateMembers",
        "guardduty:StopMonitoringMembers",
        "guardduty:DeletePublishingDestination",
        "securityhub:DisassociateMembers",
        # Config delivery redirected, and findings suppressed instead of disabled.
        "config:PutDeliveryChannel",
        "config:PutConfigurationAggregator",
        "guardduty:CreateIPSet",
        "guardduty:UpdateTrustedEntitySet",
        "securityhub:UpdateStandardsControl",
        "securityhub:BatchUpdateStandardsControlAssociations",
        "securityhub:CreateAutomationRuleV2",
        "securityhub:DisableSecurityHubV2",
        "access-analyzer:CreateArchiveRule",
        "access-analyzer:ApplyArchiveRule",
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


def _launch(principal=WORKLOAD, **context):
    instance = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/*"
    return req("ec2:RunInstances", principal, resource=instance, **{"ec2:MetadataHttpTokens": "required", **context})


def test_imds_hop_limit_stays_open_by_default(commercial):
    assert "RequireImdsHopLimitOne" not in commercial.scps_raw["data-and-compute"]
    assert decide(commercial, _launch(**{"ec2:MetadataHttpPutResponseHopLimit": "2"})) is Decision.ALLOW


def test_containers_cannot_be_given_a_route_to_the_instance_role(hop_locked):
    hop_one = _launch(**{"ec2:MetadataHttpPutResponseHopLimit": "1"})
    hop_two = _launch(**{"ec2:MetadataHttpPutResponseHopLimit": "2"})
    assert decide(hop_locked, hop_one) is Decision.ALLOW
    assert decide(hop_locked, hop_two) is Decision.EXPLICIT_DENY
    # Leaving it out is denied too: the AMI's default can be 2.
    assert decide(hop_locked, _launch()) is Decision.EXPLICIT_DENY


def _modify_metadata(principal=WORKLOAD, **context):
    instance = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0abc"
    return req("ec2:ModifyInstanceMetadataOptions", principal, resource=instance, **context)


def test_imds_can_be_upgraded_but_not_downgraded(commercial):
    assert decide(commercial, _modify_metadata(**{"ec2:Attribute/HttpTokens": "required"})) is Decision.ALLOW
    assert decide(commercial, _modify_metadata(**{"ec2:Attribute/HttpTokens": "optional"})) is Decision.EXPLICIT_DENY
    # The instance's current setting is not the requested one.
    downgrade = {"ec2:MetadataHttpTokens": "required", "ec2:Attribute/HttpTokens": "optional"}
    assert decide(commercial, _modify_metadata(**downgrade)) is Decision.EXPLICIT_DENY
    upgrade = {"ec2:MetadataHttpTokens": "optional", "ec2:Attribute/HttpTokens": "required"}
    assert decide(commercial, _modify_metadata(**upgrade)) is Decision.ALLOW
    # Without HttpTokens the request cannot show it keeps IMDSv2.
    assert decide(commercial, _modify_metadata()) is Decision.EXPLICIT_DENY


def test_hop_limit_cannot_be_raised_after_launch(hop_locked):
    keep = {"ec2:Attribute/HttpTokens": "required"}
    hop_one = _modify_metadata(**keep, **{"ec2:Attribute/HttpPutResponseHopLimit": "1"})
    hop_two = _modify_metadata(
        **keep, **{"ec2:MetadataHttpPutResponseHopLimit": "1", "ec2:Attribute/HttpPutResponseHopLimit": "2"}
    )
    assert decide(hop_locked, hop_one) is Decision.ALLOW
    assert decide(hop_locked, hop_two) is Decision.EXPLICIT_DENY
    assert decide(hop_locked, _modify_metadata(**keep)) is Decision.EXPLICIT_DENY


def test_exempt_roles_can_launch_with_a_higher_hop_limit(hop_locked):
    hop_two = _launch(BREAKGLASS, **{"ec2:MetadataHttpPutResponseHopLimit": "2"})
    assert decide(hop_locked, hop_two) is Decision.ALLOW


def test_hop_limit_rule_only_applies_to_the_instance_resource(hop_locked):
    subnet = f"arn:aws:ec2:us-east-1:{ACCOUNT}:subnet/subnet-0abc"
    assert decide(hop_locked, req("ec2:RunInstances", resource=subnet)) is Decision.ALLOW


def test_data_and_compute_bundle_with_hop_limit_fits_the_scp_size_limit(hop_locked):
    assert len(hop_locked.scps_raw["data-and-compute"]) <= SCP_MAX_CHARS


def test_data_and_compute_bundle_with_every_option_fits_the_scp_size_limit(data_locked):
    assert len(data_locked.scps_raw["data-and-compute"]) <= SCP_MAX_CHARS


# --- instance termination and stop protection (Amazon, 2025-12-16) --------

INSTANCE = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0abc"
DEPLOY = f"arn:aws:iam::{ACCOUNT}:role/security-platform-deploy"
PROTECTION_SIDS = {
    "DenyInstanceDisableApiTerminationChange",
    "DenyInstanceDisableApiStopChange",
    "DenyInstanceProtectionAttributeChange",
}


def _modify(principal=WORKLOAD, resource=INSTANCE, **context):
    return req("ec2:ModifyInstanceAttribute", principal, resource=resource, **context)


def test_instance_protection_stays_open_by_default(commercial):
    raw = commercial.scps_raw["data-and-compute"]
    assert not any(sid in raw for sid in PROTECTION_SIDS)
    assert decide(commercial, _modify(**{"ec2:Attribute/DisableApiTermination": "true"})) is Decision.ALLOW


@pytest.mark.parametrize(
    "context",
    [
        {"ec2:Attribute/DisableApiTermination": "true"},
        {"ec2:Attribute/DisableApiTermination": "false"},
        {"ec2:Attribute/DisableApiStop": "true"},
        {"ec2:Attribute": "disableApiTermination"},
        {"ec2:Attribute": "DisableApiStop"},
    ],
)
def test_stolen_credentials_cannot_lock_or_unlock_an_instance(protection_locked, context):
    assert decide(protection_locked, _modify(**context)) is Decision.EXPLICIT_DENY


@pytest.mark.parametrize("principal", [BREAKGLASS, PIPELINE, DEPLOY])
def test_exempt_and_listed_roles_can_change_instance_protection(protection_locked, principal):
    request = _modify(principal, **{"ec2:Attribute/DisableApiTermination": "true"})
    assert decide(protection_locked, request) is Decision.ALLOW


@pytest.mark.parametrize(
    "context",
    [
        {"ec2:Attribute/InstanceType": "m7i.large"},
        {"ec2:Attribute": "instanceType"},
        {},
    ],
)
def test_other_instance_attribute_changes_still_work(protection_locked, context):
    assert decide(protection_locked, _modify(**context)) is Decision.ALLOW


def test_protection_rule_only_applies_to_the_instance_resource(protection_locked):
    group = f"arn:aws:ec2:us-east-1:{ACCOUNT}:security-group/sg-0abc"
    request = _modify(resource=group, **{"ec2:Attribute/DisableApiTermination": "true"})
    assert decide(protection_locked, request) is Decision.ALLOW


# --- Athena default result bucket (CVE-2026-118029) -------------------------

ORG = "o-exampleorg1"
ATHENA_BUCKET = f"arn:aws:s3:::aws-athena-query-results-{ACCOUNT}-us-east-1"


def _athena(action, resource, principal=WORKLOAD, **extra):
    return req(action, principal, resource, **{"aws:PrincipalOrgID": ORG, **extra})


@pytest.mark.parametrize("action", ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"])
def test_athena_results_bucket_owned_outside_the_org_is_denied(data_locked, action):
    resource = ATHENA_BUCKET if action in {"s3:ListBucket", "s3:GetBucketLocation"} else f"{ATHENA_BUCKET}/q/1.csv"
    other_org = _athena(action, resource, **{"aws:ResourceOrgID": "o-attacker000"})
    # A standalone account has no aws:ResourceOrgID at all.
    standalone = _athena(action, resource)
    assert decide(data_locked, other_org) is Decision.EXPLICIT_DENY
    assert decide(data_locked, standalone) is Decision.EXPLICIT_DENY
    assert decide(data_locked, _athena(action, resource, BREAKGLASS)) is Decision.EXPLICIT_DENY


def test_athena_results_bucket_inside_the_org_is_allowed(data_locked):
    own = _athena("s3:PutObject", f"{ATHENA_BUCKET}/q/1.csv", **{"aws:ResourceOrgID": ORG})
    assert decide(data_locked, own) is Decision.ALLOW


def test_athena_rule_only_matches_the_default_bucket_name(data_locked):
    other = _athena("s3:GetObject", "arn:aws:s3:::aws-athena-query-results-shared/q/1.csv")
    assert decide(data_locked, other) is Decision.ALLOW


def test_athena_rule_is_off_by_default(commercial):
    assert decide(commercial, _athena("s3:GetObject", f"{ATHENA_BUCKET}/q/1.csv")) is Decision.ALLOW


# --- KMS keys behind the organization network perimeter (Binance, 2026) -----

PERIMETER_KEY = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/1234abcd-12ab-34cd-56ef-1234567890ab"
PERIMETER_TAG = {"aws:ResourceTag/guardrails:network-perimeter": "true"}
KMS_PERIMETER_ACTIONS = [
    "kms:Sign",
    "kms:Decrypt",
    "kms:GenerateDataKey",
    "kms:GenerateDataKeyPair",
    "kms:ReEncryptFrom",
    "kms:ReplicateKey",
    "kms:GenerateMac",
    "kms:DeriveSharedSecret",
    "kms:CreateGrant",
    "kms:PutKeyPolicy",
    "kms:TagResource",
    "kms:UntagResource",
]


def _kms(action, principal=WORKLOAD, tagged=True, **extra):
    tags = PERIMETER_TAG if tagged else {}
    return req(action, principal, PERIMETER_KEY, **{"aws:PrincipalOrgID": ORG, **tags, **extra})


@pytest.mark.parametrize("action", KMS_PERIMETER_ACTIONS)
def test_stolen_credentials_cannot_use_a_perimeter_key_from_outside(data_locked, action):
    # Public endpoint: no aws:VpceOrgID at all.
    assert decide(data_locked, _kms(action)) is Decision.EXPLICIT_DENY
    # The attacker's own VPC endpoint carries their organization's ID.
    assert decide(data_locked, _kms(action, **{"aws:VpceOrgID": "o-attacker000"})) is Decision.EXPLICIT_DENY


@pytest.mark.parametrize("action", KMS_PERIMETER_ACTIONS)
def test_perimeter_key_works_through_an_org_vpc_endpoint(data_locked, action):
    assert decide(data_locked, _kms(action, **{"aws:VpceOrgID": ORG})) is Decision.ALLOW


def test_aws_services_acting_for_the_caller_are_not_blocked(data_locked):
    # S3 SSE-KMS and EBS call KMS with the caller's identity but without the
    # caller's VPC endpoint context.
    assert decide(data_locked, _kms("kms:Decrypt", **{"aws:ViaAWSService": "true"})) is Decision.ALLOW
    assert decide(data_locked, _kms("kms:Decrypt", **{"aws:PrincipalIsAWSService": "true"})) is Decision.ALLOW


def test_untagged_keys_and_other_kms_reads_are_untouched(data_locked):
    assert decide(data_locked, _kms("kms:Sign", tagged=False)) is Decision.ALLOW
    assert decide(data_locked, _kms("kms:GetPublicKey")) is Decision.ALLOW
    assert decide(data_locked, _kms("kms:DescribeKey")) is Decision.ALLOW


def test_break_glass_can_reach_a_perimeter_key_from_outside(data_locked):
    assert decide(data_locked, _kms("kms:PutKeyPolicy", BREAKGLASS)) is Decision.ALLOW


def test_kms_perimeter_rule_is_off_by_default(commercial):
    assert decide(commercial, _kms("kms:Sign")) is Decision.ALLOW


@pytest.mark.parametrize(
    "action",
    ["ec2:DisableEbsEncryptionByDefault", "s3:PutAccountPublicAccessBlock", "ec2:ModifyInstanceMetadataOptions"],
)
def test_account_level_data_protections_are_locked(commercial, action):
    assert decide(commercial, req(action)) is Decision.EXPLICIT_DENY
    assert decide(commercial, req(action, BREAKGLASS)) is Decision.ALLOW


# --- resource sharing ------------------------------------------------------


@pytest.mark.parametrize("action", ["ram:CreateResourceShare", "ram:UpdateResourceShare"])
def test_resource_shares_cannot_allow_external_principals(commercial, action):
    external = req(action, **{"ram:RequestedAllowsExternalPrincipals": "true"})
    assert decide(commercial, external) is Decision.EXPLICIT_DENY


@pytest.mark.parametrize("action", ["ram:CreateResourceShare", "ram:UpdateResourceShare"])
def test_resource_shares_inside_the_organization_are_allowed(commercial, action):
    internal = req(action, **{"ram:RequestedAllowsExternalPrincipals": "false"})
    assert decide(commercial, internal) is Decision.ALLOW


def test_nothing_new_can_join_an_existing_external_share(commercial):
    external = req("ram:AssociateResourceShare", **{"ram:AllowsExternalPrincipals": "true"})
    internal = req("ram:AssociateResourceShare", **{"ram:AllowsExternalPrincipals": "false"})
    assert decide(commercial, external) is Decision.EXPLICIT_DENY
    assert decide(commercial, internal) is Decision.ALLOW


def test_break_glass_can_still_share_externally(commercial):
    external = req("ram:CreateResourceShare", BREAKGLASS, **{"ram:RequestedAllowsExternalPrincipals": "true"})
    assert decide(commercial, external) is Decision.ALLOW


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
        # CloudFront certificates live in us-east-1; billing moved off aws-portal.
        ("acm:RequestCertificate", "eu-west-1", Decision.ALLOW),
        ("billing:GetBillingPreferences", "eu-west-1", Decision.ALLOW),
        ("ecr-public:CreateRepository", "eu-west-1", Decision.ALLOW),
        ("notifications-contacts:CreateEmailContact", "eu-west-1", Decision.ALLOW),
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


VENDOR_ROLE = f"arn:aws:iam::{ACCOUNT}:role/vendor-fireworks-evals"
VENDOR_USER = f"arn:aws:iam::{ACCOUNT}:user/vendor-fireworks-datasets"
VENDOR_IP = "203.0.113.40"
ATTACKER_IP = "198.51.100.200"


def vendor_req(action, principal=VENDOR_ROLE, source_ip=VENDOR_IP, **extra):
    if source_ip is not None:
        extra["aws:SourceIp"] = source_ip
    return req(action, principal, **extra)


def test_no_vendor_statement_by_default(commercial):
    assert "DenyVendorOffNetwork" not in commercial.scps_raw["core"]


@pytest.mark.parametrize("principal", [VENDOR_ROLE, VENDOR_USER])
def test_vendor_credentials_work_from_the_vendors_ranges(vendor_locked, principal):
    assert decide(vendor_locked, vendor_req("s3:GetObject", principal)) is Decision.ALLOW
    assert decide(vendor_locked, vendor_req("bedrock:InvokeModel", principal, "2001:db8::40")) is Decision.ALLOW


@pytest.mark.parametrize("principal", [VENDOR_ROLE, VENDOR_USER])
@pytest.mark.parametrize("action", ["s3:GetObject", "bedrock:InvokeModel", "sts:AssumeRole", "iam:UntagRole"])
def test_stolen_vendor_credentials_fail_from_elsewhere(vendor_locked, principal, action):
    assert decide(vendor_locked, vendor_req(action, principal, ATTACKER_IP)) is Decision.EXPLICIT_DENY


def test_vendor_credentials_fail_through_a_vpc_endpoint(vendor_locked):
    # VPC endpoint calls carry no aws:SourceIp, so they are off the vendor's ranges.
    request = vendor_req("s3:GetObject", source_ip=None, **{"aws:SourceVpce": "vpce-0abc"})
    assert decide(vendor_locked, request) is Decision.EXPLICIT_DENY


def test_one_vendors_range_does_not_admit_another(vendor_locked):
    other = f"arn:aws:iam::{ACCOUNT}:role/vendor-notetaker-sync"
    assert decide(vendor_locked, vendor_req("s3:GetObject", other, VENDOR_IP)) is Decision.EXPLICIT_DENY
    assert decide(vendor_locked, vendor_req("s3:GetObject", other, "192.0.2.9")) is Decision.ALLOW


def test_aws_service_calls_for_a_vendor_are_skipped(vendor_locked):
    # AWS redacts network context when S3 calls KMS for the vendor.
    request = vendor_req("kms:Decrypt", source_ip=None, **{"aws:ViaAWSService": "true"})
    assert decide(vendor_locked, request) is Decision.ALLOW


@pytest.mark.parametrize("principal", [WORKLOAD, BREAKGLASS])
def test_other_principals_are_untouched_by_vendor_ranges(vendor_locked, principal):
    assert decide(vendor_locked, vendor_req("s3:GetObject", principal, ATTACKER_IP)) is Decision.ALLOW


def test_core_bundle_with_every_optional_statement_and_two_vendors_fits(ssc_locked):
    assert len(ssc_locked.scps_raw["core"]) <= SCP_MAX_CHARS


def test_known_limit_a_session_chained_from_the_vendor_role_is_not_covered(vendor_locked):
    # Documented limit: a role the vendor assumed on its own network has its own
    # ARN, so it must be listed too. This pins the behavior so the docs stay true.
    chained = f"arn:aws:iam::{ACCOUNT}:role/eval-dataset-reader"
    assert decide(vendor_locked, vendor_req("s3:GetObject", chained, ATTACKER_IP)) is Decision.ALLOW
