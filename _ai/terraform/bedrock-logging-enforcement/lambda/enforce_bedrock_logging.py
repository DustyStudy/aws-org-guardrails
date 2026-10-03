"""
Checks the account's Bedrock model invocation logging configuration on a
schedule and re-enables it (pointed at a designated S3 bucket and/or
CloudWatch Logs group) if it's missing or was disabled, notifying via
SNS. Bedrock model invocation logging is the only audit trail of what
prompts and completions actually passed through your models - it's a
single API call to turn off, and easy to not notice happened.

Env vars:
  SNS_TOPIC_ARN          - where to send drift notifications
  S3_BUCKET_NAME         - bucket to log invocations to (required)
  S3_KEY_PREFIX          - optional key prefix within the bucket
  CLOUDWATCH_LOG_GROUP   - optional CloudWatch Logs group to also log to
  CLOUDWATCH_ROLE_ARN    - IAM role Bedrock assumes to write to that log group
                           (required if CLOUDWATCH_LOG_GROUP is set)
  LOG_TEXT               - "true"/"false" - log text prompts/completions (default "true")
  LOG_IMAGE              - "true"/"false" - log image inputs/outputs (default "false")
  LOG_EMBEDDING          - "true"/"false" - log embedding inputs (default "false")
"""

import os
import json
import logging

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

bedrock = boto3.client("bedrock")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
S3_BUCKET_NAME = os.environ.get("S3_BUCKET_NAME")
S3_KEY_PREFIX = os.environ.get("S3_KEY_PREFIX", "")
CLOUDWATCH_LOG_GROUP = os.environ.get("CLOUDWATCH_LOG_GROUP")
CLOUDWATCH_ROLE_ARN = os.environ.get("CLOUDWATCH_ROLE_ARN")
LOG_TEXT = os.environ.get("LOG_TEXT", "true").lower() == "true"
LOG_IMAGE = os.environ.get("LOG_IMAGE", "false").lower() == "true"
LOG_EMBEDDING = os.environ.get("LOG_EMBEDDING", "false").lower() == "true"


def _notify(subject, message):
    if not SNS_TOPIC_ARN:
        logger.info("SNS_TOPIC_ARN not set, skipping notification")
        return
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject[:100], Message=message)
    except ClientError:
        logger.exception("Failed to publish SNS notification")


def _desired_logging_config():
    config = {
        "textDataDeliveryEnabled": LOG_TEXT,
        "imageDataDeliveryEnabled": LOG_IMAGE,
        "embeddingDataDeliveryEnabled": LOG_EMBEDDING,
    }
    if S3_BUCKET_NAME:
        config["s3Config"] = {"bucketName": S3_BUCKET_NAME, "keyPrefix": S3_KEY_PREFIX}
    if CLOUDWATCH_LOG_GROUP and CLOUDWATCH_ROLE_ARN:
        config["cloudWatchConfig"] = {
            "logGroupName": CLOUDWATCH_LOG_GROUP,
            "roleArn": CLOUDWATCH_ROLE_ARN,
        }
    return config


def _get_current_config():
    try:
        resp = bedrock.get_model_invocation_logging_configuration()
        return resp.get("loggingConfig")
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return None
        raise


def _is_compliant(current, desired):
    if not current:
        return False
    for flag in ("textDataDeliveryEnabled", "imageDataDeliveryEnabled", "embeddingDataDeliveryEnabled"):
        if bool(current.get(flag)) != desired[flag]:
            return False
    if S3_BUCKET_NAME and current.get("s3Config", {}).get("bucketName") != S3_BUCKET_NAME:
        return False
    if CLOUDWATCH_LOG_GROUP and current.get("cloudWatchConfig", {}).get("logGroupName") != CLOUDWATCH_LOG_GROUP:
        return False
    return True


def lambda_handler(event, context):
    logger.info("Checking Bedrock model invocation logging configuration")

    if not S3_BUCKET_NAME and not (CLOUDWATCH_LOG_GROUP and CLOUDWATCH_ROLE_ARN):
        logger.error("Neither S3_BUCKET_NAME nor a complete CloudWatch destination is configured - nothing to enforce")
        return {"statusCode": 500, "body": "no logging destination configured"}

    desired = _desired_logging_config()
    current = _get_current_config()

    if _is_compliant(current, desired):
        logger.info("Bedrock model invocation logging is already compliant")
        return {"statusCode": 200, "body": json.dumps({"compliant": True})}

    logger.warning("Bedrock model invocation logging is missing or drifted - re-enabling. Current: %s", current)

    try:
        bedrock.put_model_invocation_logging_configuration(loggingConfig=desired)
    except ClientError:
        logger.exception("Failed to enable Bedrock model invocation logging")
        _notify(
            subject="FAILED to re-enable Bedrock invocation logging",
            message=f"Attempted to set logging config but the call failed. Current config was: {json.dumps(current, default=str)}",
        )
        return {"statusCode": 500, "body": "failed to enable logging"}

    _notify(
        subject="Re-enabled Bedrock model invocation logging",
        message=(
            "Bedrock model invocation logging was missing or misconfigured and has been "
            f"re-enabled.\n\nPrevious config: {json.dumps(current, default=str)}\n\n"
            f"New config: {json.dumps(desired, default=str)}"
        ),
    )
    return {"statusCode": 200, "body": json.dumps({"compliant": False, "remediated": True})}
