from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

LAMBDA = "terraform/iam-credential-hygiene/lambda/deactivate_stale_iam_keys.py"
NOW = datetime.now(timezone.utc)


def _days_ago(days):
    return NOW - timedelta(days=days)


def _key(key_id, age_days, status="Active"):
    return {"AccessKeyId": key_id, "CreateDate": _days_ago(age_days), "Status": status}


@pytest.fixture
def make_fn(load_lambda):
    def _make(users, keys, last_used, tags=None, **env):
        module = load_lambda(LAMBDA, SNS_TOPIC_ARN="arn:aws:sns:us-east-1:123456789012:alerts", **env)
        iam = MagicMock()

        def paginator(name):
            p = MagicMock()
            if name == "list_users":
                p.paginate.return_value = [{"Users": [{"UserName": u} for u in users]}]
            else:
                p.paginate.side_effect = lambda UserName: [{"AccessKeyMetadata": keys.get(UserName, [])}]
            return p

        iam.get_paginator.side_effect = paginator
        iam.get_access_key_last_used.side_effect = lambda AccessKeyId: {
            "AccessKeyLastUsed": {"LastUsedDate": last_used[AccessKeyId]} if AccessKeyId in last_used else {}
        }
        if isinstance(tags, Exception):
            iam.list_user_tags.side_effect = tags
        else:
            iam.list_user_tags.side_effect = lambda UserName: {"Tags": (tags or {}).get(UserName, [])}
        module.iam = iam
        module.sns = MagicMock()
        return module

    return _make


def _deactivated(fn):
    return {c.kwargs["AccessKeyId"] for c in fn.iam.update_access_key.call_args_list}


def test_old_key_is_deactivated_even_if_used_today(make_fn):
    fn = make_fn(["alice"], {"alice": [_key("AKIAOLD", 200)]}, {"AKIAOLD": _days_ago(0)})

    fn.lambda_handler({}, None)

    fn.iam.update_access_key.assert_called_once_with(UserName="alice", AccessKeyId="AKIAOLD", Status="Inactive")


def test_unused_key_is_deactivated(make_fn):
    fn = make_fn(["bob"], {"bob": [_key("AKIAIDLE", 120)]}, {"AKIAIDLE": _days_ago(100)})

    fn.lambda_handler({}, None)

    assert _deactivated(fn) == {"AKIAIDLE"}


def test_never_used_key_counts_from_creation(make_fn):
    fn = make_fn(["carol"], {"carol": [_key("AKIANEVER", 95), _key("AKIANEW", 5)]}, {})

    fn.lambda_handler({}, None)

    assert _deactivated(fn) == {"AKIANEVER"}


def test_fresh_active_key_is_kept(make_fn):
    fn = make_fn(["dan"], {"dan": [_key("AKIAFRESH", 30)]}, {"AKIAFRESH": _days_ago(1)})

    fn.lambda_handler({}, None)

    fn.iam.update_access_key.assert_not_called()
    fn.sns.publish.assert_not_called()


def test_already_inactive_key_is_ignored(make_fn):
    fn = make_fn(["erin"], {"erin": [_key("AKIAOFF", 400, status="Inactive")]}, {})

    fn.lambda_handler({}, None)

    fn.iam.update_access_key.assert_not_called()


def test_exempt_user_is_skipped(make_fn):
    fn = make_fn(
        ["breakglass"],
        {"breakglass": [_key("AKIABG", 400)]},
        {},
        tags={"breakglass": [{"Key": "credential-hygiene-exempt", "Value": "true"}]},
        EXEMPT_TAG_KEY="credential-hygiene-exempt",
    )

    fn.lambda_handler({}, None)

    fn.iam.update_access_key.assert_not_called()


def test_exempt_tag_value_must_match_when_set(make_fn):
    fn = make_fn(
        ["frank"],
        {"frank": [_key("AKIAF", 400)]},
        {},
        tags={"frank": [{"Key": "exempt", "Value": "no"}]},
        EXEMPT_TAG_KEY="exempt",
        EXEMPT_TAG_VALUE="yes",
    )

    fn.lambda_handler({}, None)

    assert _deactivated(fn) == {"AKIAF"}


def test_unreadable_tags_fail_safe(make_fn):
    fn = make_fn(
        ["grace"],
        {"grace": [_key("AKIAG", 400)]},
        {},
        tags=ClientError({"Error": {"Code": "AccessDenied"}}, "ListUserTags"),
        EXEMPT_TAG_KEY="exempt",
    )

    fn.lambda_handler({}, None)

    fn.iam.update_access_key.assert_not_called()


def test_summary_lists_every_deactivated_key(make_fn):
    fn = make_fn(["h"], {"h": [_key("AKIA1", 300), _key("AKIA2", 300)]}, {})

    fn.lambda_handler({}, None)

    kwargs = fn.sns.publish.call_args.kwargs
    assert kwargs["Subject"] == "Deactivated 2 stale IAM access key(s)"
    assert "AKIA1" in kwargs["Message"] and "AKIA2" in kwargs["Message"]
