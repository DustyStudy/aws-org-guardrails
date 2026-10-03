import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

LAMBDA = "modules/bedrock-logging-enforcement/lambda/enforce_bedrock_logging.py"
COMPLIANT = {
    "textDataDeliveryEnabled": True,
    "imageDataDeliveryEnabled": False,
    "embeddingDataDeliveryEnabled": False,
    "s3Config": {"bucketName": "invocation-logs", "keyPrefix": ""},
}


@pytest.fixture
def make_fn(load_lambda):
    def _make(current=None, not_found=False, **env):
        settings = {"SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:alerts", "S3_BUCKET_NAME": "invocation-logs"}
        settings.update(env)
        module = load_lambda(LAMBDA, **settings)
        module.bedrock = MagicMock()
        if not_found:
            module.bedrock.get_model_invocation_logging_configuration.side_effect = ClientError(
                {"Error": {"Code": "ResourceNotFoundException"}}, "GetModelInvocationLoggingConfiguration"
            )
        else:
            module.bedrock.get_model_invocation_logging_configuration.return_value = {"loggingConfig": current}
        module.sns = MagicMock()
        return module

    return _make


def test_compliant_config_is_left_alone(make_fn):
    fn = make_fn(current=COMPLIANT)

    response = fn.lambda_handler({}, None)

    assert json.loads(response["body"]) == {"compliant": True}
    fn.bedrock.put_model_invocation_logging_configuration.assert_not_called()
    fn.sns.publish.assert_not_called()


def test_missing_config_is_re_enabled_and_notified(make_fn):
    fn = make_fn(not_found=True)

    fn.lambda_handler({}, None)

    config = fn.bedrock.put_model_invocation_logging_configuration.call_args.kwargs["loggingConfig"]
    assert config["s3Config"]["bucketName"] == "invocation-logs"
    assert config["textDataDeliveryEnabled"] is True
    assert "Re-enabled" in fn.sns.publish.call_args.kwargs["Subject"]


def test_disabled_text_logging_counts_as_drift(make_fn):
    fn = make_fn(current={**COMPLIANT, "textDataDeliveryEnabled": False})

    fn.lambda_handler({}, None)

    fn.bedrock.put_model_invocation_logging_configuration.assert_called_once()


def test_logging_to_another_bucket_counts_as_drift(make_fn):
    fn = make_fn(current={**COMPLIANT, "s3Config": {"bucketName": "somewhere-else"}})

    fn.lambda_handler({}, None)

    fn.bedrock.put_model_invocation_logging_configuration.assert_called_once()


def test_cloudwatch_destination_is_included(make_fn):
    fn = make_fn(
        not_found=True,
        CLOUDWATCH_LOG_GROUP="/bedrock/invocations",
        CLOUDWATCH_ROLE_ARN="arn:aws:iam::123456789012:role/bedrock-logs",
    )

    fn.lambda_handler({}, None)

    config = fn.bedrock.put_model_invocation_logging_configuration.call_args.kwargs["loggingConfig"]
    assert config["cloudWatchConfig"] == {
        "logGroupName": "/bedrock/invocations",
        "roleArn": "arn:aws:iam::123456789012:role/bedrock-logs",
    }


def test_no_destination_refuses_to_act(make_fn):
    fn = make_fn(current=None, S3_BUCKET_NAME="")

    response = fn.lambda_handler({}, None)

    assert response["statusCode"] == 500
    fn.bedrock.put_model_invocation_logging_configuration.assert_not_called()


def test_failed_re_enable_is_reported(make_fn):
    fn = make_fn(current=None)
    fn.bedrock.put_model_invocation_logging_configuration.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied"}}, "PutModelInvocationLoggingConfiguration"
    )

    response = fn.lambda_handler({}, None)

    assert response["statusCode"] == 500
    assert "FAILED" in fn.sns.publish.call_args.kwargs["Subject"]


def test_unexpected_read_error_propagates(make_fn):
    fn = make_fn()
    fn.bedrock.get_model_invocation_logging_configuration.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied"}}, "GetModelInvocationLoggingConfiguration"
    )

    with pytest.raises(ClientError):
        fn.lambda_handler({}, None)
