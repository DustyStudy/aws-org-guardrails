"""Checks that the evaluator follows IAM's documented semantics.

The guardrail tests are only as good as the evaluator they run on, so each
rule the guardrails depend on is pinned down here against a hand-written policy.
"""

import pytest

from guardrails_tools.iam_eval import (
    Decision,
    Request,
    UnsupportedPolicyFeature,
    evaluate,
    glob_match,
    scp_decision,
)


def policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


ALLOW_ALL = {"Effect": "Allow", "Action": "*", "Resource": "*"}


def test_no_matching_statement_is_implicit_deny():
    assert evaluate([policy()], Request("s3:GetObject")) is Decision.IMPLICIT_DENY


def test_explicit_deny_beats_allow_regardless_of_order():
    deny = {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"}
    assert evaluate([policy(ALLOW_ALL, deny)], Request("s3:GetObject")) is Decision.EXPLICIT_DENY
    assert evaluate([policy(deny), policy(ALLOW_ALL)], Request("s3:GetObject")) is Decision.EXPLICIT_DENY


def test_action_match_is_case_insensitive_with_wildcards():
    deny = {"Effect": "Deny", "Action": "CloudTrail:Stop*", "Resource": "*"}
    assert scp_decision([policy(deny)], Request("cloudtrail:StopLogging")) is Decision.EXPLICIT_DENY
    assert scp_decision([policy(deny)], Request("cloudtrail:StartLogging")) is Decision.ALLOW


def test_resource_match_is_case_sensitive():
    deny = {"Effect": "Deny", "Action": "*", "Resource": "arn:aws:s3:::Logs/*"}
    assert scp_decision([policy(deny)], Request("s3:GetObject", "arn:aws:s3:::logs/a")) is Decision.ALLOW


def test_not_action_matches_everything_else():
    deny = {"Effect": "Deny", "NotAction": ["iam:*"], "Resource": "*"}
    assert scp_decision([policy(deny)], Request("iam:CreateRole")) is Decision.ALLOW
    assert scp_decision([policy(deny)], Request("ec2:RunInstances")) is Decision.EXPLICIT_DENY


def test_not_resource_matches_everything_else():
    deny = {"Effect": "Deny", "Action": "iam:PassRole", "NotResource": "arn:aws:iam::1:role/app/*"}
    assert scp_decision([policy(deny)], Request("iam:PassRole", "arn:aws:iam::1:role/app/x")) is Decision.ALLOW
    assert scp_decision([policy(deny)], Request("iam:PassRole", "arn:aws:iam::1:role/Admin")) is Decision.EXPLICIT_DENY


def test_wildcard_spans_colons_and_slashes():
    assert glob_match("arn:aws:iam::*:role/ops-*", "arn:aws:iam::123456789012:role/ops-a/b")
    assert not glob_match("arn:aws:iam::?:root", "arn:aws:iam::12:root")


@pytest.mark.parametrize(
    ("operator", "expected"),
    [
        ("StringEquals", False),
        ("StringNotEquals", True),
        ("ArnLike", False),
        ("ArnNotLike", True),
        ("StringEqualsIfExists", True),
        ("StringNotEqualsIfExists", True),
    ],
)
def test_missing_key_semantics(operator, expected):
    deny = {"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {operator: {"aws:SomeKey": "x"}}}
    denied = scp_decision([policy(deny)], Request("s3:GetObject")) is Decision.EXPLICIT_DENY
    assert denied is expected


def test_null_operator_checks_presence():
    deny = {"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {"Null": {"aws:SourceIp": "true"}}}
    assert scp_decision([policy(deny)], Request("s3:GetObject")) is Decision.EXPLICIT_DENY
    present = Request("s3:GetObject", context={"aws:SourceIp": "10.0.0.1"})
    assert scp_decision([policy(deny)], present) is Decision.ALLOW


def test_multiple_values_in_one_condition_are_ored_and_negation_applies_to_all():
    deny = {
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
        "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1", "us-west-2"]}},
    }
    for region, expected in [
        ("us-east-1", Decision.ALLOW),
        ("us-west-2", Decision.ALLOW),
        ("eu-west-1", Decision.EXPLICIT_DENY),
    ]:
        req = Request("ec2:RunInstances", context={"aws:RequestedRegion": region})
        assert scp_decision([policy(deny)], req) is expected


def test_multiple_condition_blocks_are_anded():
    deny = {
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
        "Condition": {
            "StringNotEquals": {"aws:RequestedRegion": "us-east-1"},
            "ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/admin"},
        },
    }
    admin = {"aws:RequestedRegion": "eu-west-1", "aws:PrincipalArn": "arn:aws:iam::1:role/admin"}
    dev = {"aws:RequestedRegion": "eu-west-1", "aws:PrincipalArn": "arn:aws:iam::1:role/dev"}
    assert scp_decision([policy(deny)], Request("s3:GetObject", context=admin)) is Decision.ALLOW
    assert scp_decision([policy(deny)], Request("s3:GetObject", context=dev)) is Decision.EXPLICIT_DENY


def test_policy_variables_resolve_from_context():
    deny = {"Effect": "Deny", "Action": "*", "Resource": "arn:aws:iam::*:user/${aws:username}"}
    ctx = {"aws:username": "alice"}
    own = Request("iam:DeleteLoginProfile", "arn:aws:iam::111122223333:user/alice", ctx)
    other = Request("iam:DeleteLoginProfile", "arn:aws:iam::111122223333:user/bob", ctx)
    assert scp_decision([policy(deny)], own) is Decision.EXPLICIT_DENY
    assert scp_decision([policy(deny)], other) is Decision.ALLOW


def test_policy_variables_in_condition_values_resolve():
    deny = {
        "Effect": "Deny",
        "Action": "iam:CreateRole",
        "Resource": "*",
        "Condition": {"StringNotEquals": {"iam:PermissionsBoundary": "arn:aws:iam::${aws:PrincipalAccount}:policy/b"}},
    }
    ctx = {"aws:PrincipalAccount": "111122223333"}
    good = Request("iam:CreateRole", context={**ctx, "iam:PermissionsBoundary": "arn:aws:iam::111122223333:policy/b"})
    other = Request("iam:CreateRole", context={**ctx, "iam:PermissionsBoundary": "arn:aws:iam::444455556666:policy/b"})
    assert scp_decision([policy(deny)], good) is Decision.ALLOW
    assert scp_decision([policy(deny)], other) is Decision.EXPLICIT_DENY


@pytest.mark.parametrize("element", ["Resource", "NotResource"])
def test_policy_variable_in_resource_account_field_is_rejected(element):
    # IAM's CreatePolicy fails these with "failed legacy parsing".
    deny = {"Effect": "Deny", "Action": "*", element: "arn:aws:iam::${aws:PrincipalAccount}:policy/b"}
    with pytest.raises(UnsupportedPolicyFeature):
        evaluate([policy(deny)], Request("iam:DeletePolicy", "arn:aws:iam::111122223333:policy/b"))


def test_unresolvable_policy_variable_never_matches():
    deny = {"Effect": "Deny", "Action": "*", "Resource": "arn:aws:iam::*:user/${aws:username}"}
    req = Request("iam:DeleteLoginProfile", "arn:aws:iam::111122223333:user/alice")
    assert scp_decision([policy(deny)], req) is Decision.ALLOW


@pytest.mark.parametrize(
    "condition",
    [
        {"NumericLessThan": {"aws:MultiFactorAuthAge": "3600"}},
        {"ForAnyValue:StringEquals": {"aws:TagKeys": "a"}},
        {"DateGreaterThan": {"aws:CurrentTime": "2020-01-01T00:00:00Z"}},
    ],
)
def test_unsupported_operators_fail_loudly(condition):
    deny = {"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": condition}
    with pytest.raises(UnsupportedPolicyFeature):
        evaluate([policy(deny)], Request("s3:GetObject", context={"aws:MultiFactorAuthAge": "1"}))


def test_unknown_statement_elements_fail_loudly():
    with pytest.raises(UnsupportedPolicyFeature):
        evaluate(
            [policy({"Effect": "Deny", "Action": "*", "Resource": "*", "Principal": "*"})], Request("s3:GetObject")
        )
