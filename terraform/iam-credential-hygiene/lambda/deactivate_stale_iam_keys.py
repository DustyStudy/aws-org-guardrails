"""
Scans every IAM user's access keys and deactivates (does not delete) any
key that's either too old or unused for too long, then publishes a summary
to SNS. Invoked on a schedule (EventBridge Scheduler / CloudWatch Events
rate/cron expression) - see the Terraform in this tool.

Deactivating rather than deleting means a false positive is a quick
`aws iam update-access-key --status Active` away from being reversible,
rather than requiring the user to generate a brand new key pair.

Env vars:
  SNS_TOPIC_ARN      - where to send the summary notification
  MAX_KEY_AGE_DAYS    - deactivate any active key older than this, regardless
                        of use (default 180)
  MAX_UNUSED_DAYS     - deactivate any active key not used in this many days,
                        or never used and older than this many days
                        (default 90)
  EXEMPT_TAG_KEY      - optional; if a user has this tag key (any value,
                        unless EXEMPT_TAG_VALUE is also set) their keys are
                        skipped entirely - use for break-glass/service
                        accounts that intentionally hold long-lived keys
  EXEMPT_TAG_VALUE    - optional; if set, the tag value must also match
"""

import os
import json
import logging
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

iam = boto3.client("iam")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
MAX_KEY_AGE_DAYS = int(os.environ.get("MAX_KEY_AGE_DAYS", "180"))
MAX_UNUSED_DAYS = int(os.environ.get("MAX_UNUSED_DAYS", "90"))
EXEMPT_TAG_KEY = os.environ.get("EXEMPT_TAG_KEY")
EXEMPT_TAG_VALUE = os.environ.get("EXEMPT_TAG_VALUE")


def _notify(subject, message):
    if not SNS_TOPIC_ARN:
        logger.info("SNS_TOPIC_ARN not set, skipping notification")
        return
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject[:100], Message=message)
    except ClientError:
        logger.exception("Failed to publish SNS notification")


def _is_exempt(user_name):
    if not EXEMPT_TAG_KEY:
        return False
    try:
        tags = iam.list_user_tags(UserName=user_name).get("Tags", [])
    except ClientError:
        # Fail safe: if we can't tell whether the user is exempt, don't
        # deactivate their keys - they may be a break-glass account.
        logger.exception("Failed to list tags for user %s - skipping user this run", user_name)
        return True
    for tag in tags:
        if tag.get("Key") == EXEMPT_TAG_KEY:
            if EXEMPT_TAG_VALUE is None or tag.get("Value") == EXEMPT_TAG_VALUE:
                return True
    return False


def _iter_users():
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            yield user


def _iter_access_keys(user_name):
    paginator = iam.get_paginator("list_access_keys")
    for page in paginator.paginate(UserName=user_name):
        for key in page.get("AccessKeyMetadata", []):
            yield key


def _days_since(dt):
    if dt is None:
        return None
    now = datetime.now(timezone.utc)
    return (now - dt).days


def _evaluate_key(user_name, key_meta):
    """Returns a reason string if the key should be deactivated, else None."""
    if key_meta.get("Status") != "Active":
        return None

    access_key_id = key_meta["AccessKeyId"]
    create_date = key_meta.get("CreateDate")
    age_days = _days_since(create_date)

    try:
        last_used_resp = iam.get_access_key_last_used(AccessKeyId=access_key_id)
    except ClientError:
        logger.exception("Failed to get last-used info for key %s (user %s)", access_key_id, user_name)
        return None

    last_used_info = last_used_resp.get("AccessKeyLastUsed", {})
    last_used_date = last_used_info.get("LastUsedDate")
    unused_days = _days_since(last_used_date) if last_used_date else age_days

    if age_days is not None and age_days > MAX_KEY_AGE_DAYS:
        return f"key age {age_days}d exceeds MAX_KEY_AGE_DAYS ({MAX_KEY_AGE_DAYS}d)"

    if unused_days is not None and unused_days > MAX_UNUSED_DAYS:
        if last_used_date:
            return f"unused for {unused_days}d (last used {last_used_date.date()}), exceeds MAX_UNUSED_DAYS ({MAX_UNUSED_DAYS}d)"
        return f"never used, {unused_days}d old, exceeds MAX_UNUSED_DAYS ({MAX_UNUSED_DAYS}d)"

    return None


def lambda_handler(event, context):
    logger.info("Starting IAM credential hygiene scan")
    deactivated = []
    errors = []

    for user in _iter_users():
        user_name = user["UserName"]

        if _is_exempt(user_name):
            logger.info("Skipping exempt user %s", user_name)
            continue

        for key_meta in _iter_access_keys(user_name):
            access_key_id = key_meta["AccessKeyId"]
            reason = _evaluate_key(user_name, key_meta)
            if not reason:
                continue

            try:
                iam.update_access_key(UserName=user_name, AccessKeyId=access_key_id, Status="Inactive")
                deactivated.append({"user": user_name, "access_key_id": access_key_id, "reason": reason})
                logger.info("Deactivated key %s for user %s: %s", access_key_id, user_name, reason)
            except ClientError:
                logger.exception("Failed to deactivate key %s for user %s", access_key_id, user_name)
                errors.append({"user": user_name, "access_key_id": access_key_id})

    if deactivated:
        lines = [f"- {d['user']} / {d['access_key_id']}: {d['reason']}" for d in deactivated]
        _notify(
            subject=f"Deactivated {len(deactivated)} stale IAM access key(s)",
            message="The following IAM access keys were deactivated (not deleted):\n\n" + "\n".join(lines),
        )

    if errors:
        logger.warning("Failed to deactivate %d key(s): %s", len(errors), errors)

    result = {"deactivated": deactivated, "errors": errors}
    logger.info("Scan complete: %s", json.dumps(result, default=str))
    return {"statusCode": 200, "body": json.dumps(result, default=str)}
