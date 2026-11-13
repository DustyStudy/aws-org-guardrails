"""Behavior tests for the rendered permissions boundary.

The boundary is evaluated on its own, which answers "does the boundary allow
this?". The real effective permission is the intersection with the
principal's identity policies, which only ever narrows these results.
"""

import json

import pytest

from guardrails_tools.iam_eval import Decision, Request, evaluate

ACCOUNT = "111122223333"
BOUNDARY_ARN = f"arn:aws:iam::{ACCOUNT}:policy/workload-permissions-boundary"
APP_ROLE = f"arn:aws:iam::{ACCOUNT}:role/workload/app"
ADMIN_ROLE = f"arn:aws:iam::{ACCOUNT}:role/Admin"


def decide(rendered, action, resource="*", **context):
    ctx = {"aws:PrincipalAccount": ACCOUNT, **context}
    return evaluate([rendered.boundary], Request(action, resource, ctx))


def test_everyday_actions_are_within_the_boundary(commercial):
    assert decide(commercial, "s3:GetObject", "arn:aws:s3:::app-bucket/key") is Decision.ALLOW
    assert decide(commercial, "lambda:CreateFunction") is Decision.ALLOW


def test_new_roles_must_carry_the_same_boundary(commercial):
    assert decide(commercial, "iam:CreateRole", APP_ROLE, **{"iam:PermissionsBoundary": BOUNDARY_ARN}) is Decision.ALLOW
    assert decide(commercial, "iam:CreateRole", APP_ROLE) is Decision.EXPLICIT_DENY
    other = f"arn:aws:iam::{ACCOUNT}:policy/wide-open"
    assert (
        decide(commercial, "iam:CreateRole", APP_ROLE, **{"iam:PermissionsBoundary": other}) is Decision.EXPLICIT_DENY
    )


def test_boundary_from_another_account_does_not_count(commercial):
    foreign = "arn:aws:iam::444455556666:policy/workload-permissions-boundary"
    assert (
        decide(commercial, "iam:CreateRole", APP_ROLE, **{"iam:PermissionsBoundary": foreign}) is Decision.EXPLICIT_DENY
    )


def test_new_roles_must_live_under_the_delegated_path(commercial):
    ctx = {"iam:PermissionsBoundary": BOUNDARY_ARN}
    assert decide(commercial, "iam:CreateRole", ADMIN_ROLE, **ctx) is Decision.EXPLICIT_DENY


@pytest.mark.parametrize("action", ["iam:DeleteRolePermissionsBoundary", "iam:DeleteUserPermissionsBoundary"])
def test_boundary_cannot_be_removed(commercial, action):
    assert decide(commercial, action, APP_ROLE) is Decision.EXPLICIT_DENY


@pytest.mark.parametrize("action", ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:DeletePolicy"])
def test_boundary_policy_itself_cannot_be_edited(commercial, action):
    assert decide(commercial, action, BOUNDARY_ARN) is Decision.EXPLICIT_DENY
    app_policy = f"arn:aws:iam::{ACCOUNT}:policy/workload/app-policy"
    assert decide(commercial, action, app_policy) is Decision.ALLOW


@pytest.mark.parametrize(
    "action", ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:DeletePolicyVersion"]
)
def test_policies_outside_the_delegated_path_cannot_be_rewritten(commercial, action):
    # A new default version would change every admin role the policy is on.
    admin_policy = f"arn:aws:iam::{ACCOUNT}:policy/AdminPolicy"
    assert decide(commercial, action, admin_policy) is Decision.EXPLICIT_DENY


@pytest.mark.parametrize(
    "action",
    [
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy",
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
        "iam:CreateServiceSpecificCredential",
        "iam:UpdateUser",
    ],
)
def test_existing_users_outside_the_delegated_path_cannot_be_taken_over(commercial, action):
    assert decide(commercial, action, f"arn:aws:iam::{ACCOUNT}:user/alice-admin") is Decision.EXPLICIT_DENY
    assert decide(commercial, action, f"arn:aws:iam::{ACCOUNT}:user/workload/ci") is Decision.ALLOW


@pytest.mark.parametrize(
    "action", ["iam:AttachGroupPolicy", "iam:PutGroupPolicy", "iam:AddUserToGroup", "iam:UpdateGroup"]
)
def test_groups_cannot_be_changed_on_any_path(commercial, action):
    # AddUserToGroup is authorized against the group only, so a delegated
    # group could take in an unbounded user and then be granted anything.
    assert decide(commercial, action, f"arn:aws:iam::{ACCOUNT}:group/Admins") is Decision.EXPLICIT_DENY
    assert decide(commercial, action, f"arn:aws:iam::{ACCOUNT}:group/workload/devs") is Decision.EXPLICIT_DENY


@pytest.mark.parametrize(
    ("role", "expected"),
    [(APP_ROLE, Decision.ALLOW), (ADMIN_ROLE, Decision.EXPLICIT_DENY)],
)
def test_pass_role_is_limited_to_delegated_roles(commercial, role, expected):
    assert decide(commercial, "iam:PassRole", role) is expected


def test_admin_roles_cannot_be_modified(commercial):
    for action in (
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "iam:DeleteRole",
    ):
        assert decide(commercial, action, ADMIN_ROLE) is Decision.EXPLICIT_DENY
        assert decide(commercial, action, APP_ROLE) is Decision.ALLOW


@pytest.mark.parametrize(
    ("action", "kind"), [("iam:PutRolePermissionsBoundary", "role"), ("iam:PutUserPermissionsBoundary", "user")]
)
def test_boundary_of_principals_outside_the_delegated_path_cannot_be_replaced(commercial, action, kind):
    # Even with this boundary: it would widen a stricter one already on an admin principal.
    ctx = {"iam:PermissionsBoundary": BOUNDARY_ARN}
    assert decide(commercial, action, f"arn:aws:iam::{ACCOUNT}:{kind}/Admin", **ctx) is Decision.EXPLICIT_DENY
    assert decide(commercial, action, f"arn:aws:iam::{ACCOUNT}:{kind}/workload/app", **ctx) is Decision.ALLOW


SAML_PROVIDER = f"arn:aws:iam::{ACCOUNT}:saml-provider/CorpIdP"
OIDC_PROVIDER = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"


@pytest.mark.parametrize(
    ("action", "provider"),
    [
        ("iam:UpdateSAMLProvider", SAML_PROVIDER),
        ("iam:DeleteSAMLProvider", SAML_PROVIDER),
        ("iam:UpdateOpenIDConnectProviderThumbprint", OIDC_PROVIDER),
        ("iam:AddClientIDToOpenIDConnectProvider", OIDC_PROVIDER),
        ("iam:RemoveClientIDFromOpenIDConnectProvider", OIDC_PROVIDER),
        ("iam:DeleteOpenIDConnectProvider", OIDC_PROVIDER),
    ],
)
def test_identity_providers_admin_roles_trust_cannot_be_rewritten(commercial, action, provider):
    assert decide(commercial, action, provider) is Decision.EXPLICIT_DENY


def test_new_identity_providers_can_still_be_created(commercial):
    # EKS IRSA creates an OIDC provider per cluster.
    oidc = f"arn:aws:iam::{ACCOUNT}:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
    assert decide(commercial, "iam:CreateOpenIDConnectProvider", oidc) is Decision.ALLOW


@pytest.mark.parametrize("action", ["organizations:DescribeOrganization", "account:PutAlternateContact"])
def test_organization_and_account_settings_are_out_of_bounds(commercial, action):
    assert decide(commercial, action) is Decision.EXPLICIT_DENY


def test_govcloud_boundary_uses_govcloud_arns(govcloud):
    gov_boundary = f"arn:aws-us-gov:iam::{ACCOUNT}:policy/workload-permissions-boundary"
    gov_app = f"arn:aws-us-gov:iam::{ACCOUNT}:role/workload/app"
    assert decide(govcloud, "iam:CreateRole", gov_app, **{"iam:PermissionsBoundary": gov_boundary}) is Decision.ALLOW
    assert (
        decide(govcloud, "iam:CreateRole", gov_app, **{"iam:PermissionsBoundary": BOUNDARY_ARN})
        is Decision.EXPLICIT_DENY
    )


@pytest.mark.parametrize(
    ("service", "expected"),
    [("ecs.amazonaws.com", Decision.ALLOW), ("sso.amazonaws.com", Decision.IMPLICIT_DENY)],
)
def test_service_linked_roles_only_for_listed_services(commercial, service, expected):
    arn = f"arn:aws:iam::{ACCOUNT}:role/aws-service-role/{service}/AWSServiceRole"
    assert decide(commercial, "iam:CreateServiceLinkedRole", arn) is expected


def test_boundary_fits_the_managed_policy_size_limit(commercial, govcloud):
    # IAM counts managed policy size without whitespace; the limit is 6,144.
    for rendered in (commercial, govcloud):
        assert len(json.dumps(rendered.boundary, separators=(",", ":"))) <= 6144


def test_pass_role_is_not_granted_by_the_broad_allow(commercial):
    # Access Analyzer flags PassRole on "*" even when a Deny narrows it, so
    # the broad Allow excludes PassRole and a scoped Allow grants it back.
    broad = next(s for s in commercial.boundary["Statement"] if s["Sid"] == "AllowWithinBoundary")
    assert "iam:PassRole" in broad["NotAction"]
    assert "iam:CreateServiceLinkedRole" in broad["NotAction"]
