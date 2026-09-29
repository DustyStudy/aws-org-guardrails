"""Behavior tests for the rendered permissions boundary.

The boundary is evaluated on its own, which answers "does the boundary allow
this?". The real effective permission is the intersection with the
principal's identity policies, which only ever narrows these results.
"""

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
    app_policy = f"arn:aws:iam::{ACCOUNT}:policy/app-policy"
    assert decide(commercial, action, app_policy) is Decision.ALLOW


@pytest.mark.parametrize(
    ("role", "expected"),
    [(APP_ROLE, Decision.ALLOW), (ADMIN_ROLE, Decision.EXPLICIT_DENY)],
)
def test_pass_role_is_limited_to_delegated_roles(commercial, role, expected):
    assert decide(commercial, "iam:PassRole", role) is expected


def test_admin_roles_cannot_be_modified(commercial):
    for action in ("iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy", "iam:DeleteRole"):
        assert decide(commercial, action, ADMIN_ROLE) is Decision.EXPLICIT_DENY
        assert decide(commercial, action, APP_ROLE) is Decision.ALLOW


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
