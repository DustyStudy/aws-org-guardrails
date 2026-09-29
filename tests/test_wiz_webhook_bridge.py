import base64
import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

LAMBDA = "terraform/wiz-finding-bridge/lambda/wiz_webhook_bridge.py"
SECRET = "s3cr3t-token-value"


@pytest.fixture
def make_fn(load_lambda):
    def _make(**env):
        module = load_lambda(
            LAMBDA,
            SNS_TOPIC_ARN="arn:aws:sns:us-east-1:123456789012:alerts",
            WEBHOOK_SECRET_ARN="arn:aws:secretsmanager:us-east-1:123456789012:secret:wiz",
            **env,
        )
        module.secretsmanager = MagicMock()
        module.secretsmanager.get_secret_value.return_value = {"SecretString": SECRET}
        module.sns = MagicMock()
        module.lambda_client = MagicMock()
        return module

    return _make


@pytest.fixture
def fn(make_fn):
    return make_fn()


def _event(payload, token=SECRET, b64=False):
    body = payload if isinstance(payload, str) else json.dumps(payload)
    if b64:
        body = base64.b64encode(body.encode()).decode()
    return {"pathParameters": {"secretToken": token}, "body": body, "isBase64Encoded": b64}


def test_wrong_token_is_rejected(fn):
    response = fn.lambda_handler(_event({"severity": "CRITICAL"}, token="guess"), None)

    assert response["statusCode"] == 401
    fn.sns.publish.assert_not_called()


def test_non_ascii_token_is_a_clean_401_not_a_crash(fn):
    response = fn.lambda_handler(_event({"severity": "CRITICAL"}, token="é" * 10), None)

    assert response["statusCode"] == 401


def test_unreadable_secret_rejects_every_delivery(fn):
    fn.secretsmanager.get_secret_value.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "GetSecretValue")

    assert fn.lambda_handler(_event({"severity": "CRITICAL"}), None)["statusCode"] == 401


def test_secret_is_cached_between_deliveries(fn):
    fn.lambda_handler(_event({"severity": "HIGH"}), None)
    fn.lambda_handler(_event({"severity": "HIGH"}), None)

    assert fn.secretsmanager.get_secret_value.call_count == 1


def test_high_finding_is_published(fn):
    fn.lambda_handler(_event({"severity": "HIGH", "title": "Public bucket", "primaryResource": {"id": "b1"}}), None)

    kwargs = fn.sns.publish.call_args.kwargs
    assert kwargs["Subject"] == "Wiz finding: Public bucket"
    assert '"id": "b1"' in kwargs["Message"]


def test_finding_below_threshold_is_dropped(fn):
    response = fn.lambda_handler(_event({"severity": "LOW", "title": "Minor"}), None)

    assert "below MIN_SEVERITY" in response["body"]
    fn.sns.publish.assert_not_called()


def test_unresolved_severity_fails_open(fn):
    fn.lambda_handler(_event({"title": "No severity field"}), None)

    assert "unresolved - check SEVERITY_FIELD_PATH" in fn.sns.publish.call_args.kwargs["Message"]


def test_nested_field_paths(make_fn):
    fn = make_fn(SEVERITY_FIELD_PATH="issue.severity", TITLE_FIELD_PATH="issue.rule.name")

    fn.lambda_handler(_event({"issue": {"severity": "critical", "rule": {"name": "Admin role"}}}), None)

    assert fn.sns.publish.call_args.kwargs["Subject"] == "Wiz finding: Admin role"


def test_subject_is_sanitized_for_sns(fn):
    fn.lambda_handler(_event({"severity": "HIGH", "title": "Line one\nLine two – café" * 5}), None)

    subject = fn.sns.publish.call_args.kwargs["Subject"]
    assert all(0x20 <= ord(ch) <= 0x7E for ch in subject)
    assert len(subject) <= 100


def test_mapped_title_invokes_remediation_lambda(make_fn):
    target = "arn:aws:lambda:us-east-1:123456789012:function:fix"
    fn = make_fn(REMEDIATION_LAMBDA_MAP=json.dumps({"Open SSH": target}))

    fn.lambda_handler(_event({"severity": "HIGH", "title": "Open SSH"}), None)

    kwargs = fn.lambda_client.invoke.call_args.kwargs
    assert kwargs["FunctionName"] == target
    assert kwargs["InvocationType"] == "Event"


def test_base64_body_is_decoded(fn):
    fn.lambda_handler(_event({"severity": "CRITICAL", "title": "Encoded"}, b64=True), None)

    assert fn.sns.publish.call_args.kwargs["Subject"] == "Wiz finding: Encoded"


def test_invalid_json_is_acknowledged_without_retry(fn):
    response = fn.lambda_handler(_event("not json"), None)

    assert response["statusCode"] == 200
    fn.sns.publish.assert_not_called()
