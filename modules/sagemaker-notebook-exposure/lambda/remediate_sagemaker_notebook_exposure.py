"""
Detects SageMaker notebook instances with DirectInternetAccess or
RootAccess enabled and remediates them. Handles three invocation shapes
so the same function serves both the event-driven and Config-rule paths:

1. CloudTrail CreateNotebookInstance/UpdateNotebookInstance event (via
   EventBridge) - a notebook was just created or reconfigured.
2. Direct invocation with {"notebook_instance_name": "..."} - used by the
   SSM Automation document triggered from an AWS Config remediation
   (catches drift / pre-existing notebooks).
3. The native "SageMaker Notebook Instance State Change" EventBridge
   event with NotebookInstanceStatus == "Stopped" - the second half of
   remediation, since SageMaker only allows changing RootAccess while the
   notebook is stopped. DirectInternetAccess cannot be changed at all on an
   existing notebook; it has to be recreated.

Remediation is necessarily two-phase because of that stop-before-update
requirement:

  Phase 1 (flag_and_stop): describe the notebook; if non-compliant, tag
  it "sagemaker-remediation-pending=true" and stop it if it's running.

  Phase 2 (finish_remediation): triggered once the notebook reaches the
  Stopped state; if it carries the pending tag, disable RootAccess. If
  DirectInternetAccess is enabled, keep the tag, leave it stopped and
  notify that it must be recreated. Otherwise remove the tag and
  optionally restart it (AUTO_RESTART, default false - leaves it stopped
  for review unless explicitly enabled).

Env vars:
  SNS_TOPIC_ARN  - where to send notifications
  AUTO_RESTART   - "true"/"false" - restart the notebook after remediation
                   completes (default "false" - leaves it stopped)
"""

import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

sagemaker = boto3.client("sagemaker")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
AUTO_RESTART = os.environ.get("AUTO_RESTART", "false").lower() == "true"
PENDING_TAG_KEY = "sagemaker-remediation-pending"


def _notify(subject, message):
    if not SNS_TOPIC_ARN:
        logger.info("SNS_TOPIC_ARN not set, skipping notification")
        return
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject[:100], Message=message)
    except ClientError:
        logger.exception("Failed to publish SNS notification")


def _is_noncompliant(description):
    return description.get("DirectInternetAccess") == "Enabled" or description.get("RootAccess") == "Enabled"


def _tag_pending(arn):
    sagemaker.add_tags(ResourceArn=arn, Tags=[{"Key": PENDING_TAG_KEY, "Value": "true"}])


def _is_tagged_pending(arn):
    tags = sagemaker.list_tags(ResourceArn=arn).get("Tags", [])
    return any(t.get("Key") == PENDING_TAG_KEY and t.get("Value") == "true" for t in tags)


def _clear_pending_tag(arn):
    sagemaker.delete_tags(ResourceArn=arn, TagKeys=[PENDING_TAG_KEY])


def _flag_and_stop(name):
    description = sagemaker.describe_notebook_instance(NotebookInstanceName=name)
    if not _is_noncompliant(description):
        logger.info("Notebook %s is compliant, nothing to do", name)
        return

    arn = description["NotebookInstanceArn"]
    status = description["NotebookInstanceStatus"]
    logger.warning(
        "Notebook %s is non-compliant (DirectInternetAccess=%s, RootAccess=%s), status=%s",
        name,
        description.get("DirectInternetAccess"),
        description.get("RootAccess"),
        status,
    )

    _tag_pending(arn)

    if status == "InService":
        sagemaker.stop_notebook_instance(NotebookInstanceName=name)
        _notify(
            subject=f"Stopping non-compliant SageMaker notebook {name}",
            message=(
                f"Notebook {name} has DirectInternetAccess="
                f"{description.get('DirectInternetAccess')} and RootAccess="
                f"{description.get('RootAccess')}. Stopping it now; root access "
                "will be disabled once it's fully stopped. Direct internet access "
                "cannot be changed in place: such a notebook stays stopped until "
                "it is recreated."
            ),
        )
    elif status == "Stopped":
        # Already stopped (e.g. flagged via the Config/drift path on a
        # notebook nobody had started) - finish remediation immediately.
        _finish_remediation(name, description)
    else:
        logger.info(
            "Notebook %s is in transitional state %s - will catch it on the next state-change event", name, status
        )


def _finish_remediation(name, description=None):
    if description is None:
        description = sagemaker.describe_notebook_instance(NotebookInstanceName=name)

    arn = description["NotebookInstanceArn"]

    if not _is_tagged_pending(arn):
        logger.info("Notebook %s stopped but has no pending-remediation tag, nothing to do", name)
        return

    if description.get("RootAccess") == "Enabled":
        try:
            sagemaker.update_notebook_instance(NotebookInstanceName=name, RootAccess="Disabled")
        except ClientError as e:
            logger.exception("Failed to update notebook %s", name)
            _notify(
                subject=f"FAILED to remediate SageMaker notebook {name}",
                message=(
                    f"Notebook {name} is stopped and still has RootAccess=Enabled. The update failed: "
                    f"{e.response.get('Error', {}).get('Message', str(e))} "
                    "Manual remediation is required. The pending-remediation tag has been left in place."
                ),
            )
            return
        # The notebook goes Updating, then Stopped again; that event finishes
        # the job, so the tag stays and nothing starts it mid-update.
        logger.info("Disabled RootAccess on %s, waiting for it to return to Stopped", name)
        return

    if description.get("DirectInternetAccess") == "Enabled":
        # UpdateNotebookInstance has no DirectInternetAccess parameter; only
        # recreating the notebook in a VPC subnet with it Disabled fixes it.
        # Keep the tag; if someone starts it, the InService event stops it.
        _notify(
            subject=f"SageMaker notebook {name} needs to be recreated",
            message=(
                f"Notebook {name} has DirectInternetAccess=Enabled, which cannot be changed in place. "
                "It has been left stopped with the pending-remediation tag. Copy off any data on its "
                "volume, then recreate it in a VPC subnet with DirectInternetAccess=Disabled."
            ),
        )
        return
    _clear_pending_tag(arn)

    restarted = False
    if AUTO_RESTART:
        sagemaker.start_notebook_instance(NotebookInstanceName=name)
        restarted = True

    _notify(
        subject=f"Remediated SageMaker notebook {name}",
        message=(
            f"Notebook {name} is compliant again. "
            + ("It has been restarted." if restarted else "It has been left stopped for review.")
        ),
    )


def _handle_cloudtrail_event(event):
    detail = event.get("detail", {})
    request_params = detail.get("requestParameters", {}) or {}
    name = request_params.get("notebookInstanceName")
    if not name:
        logger.warning("No notebookInstanceName in CloudTrail event, skipping")
        return
    _flag_and_stop(name)


def _handle_state_change_event(event):
    detail = event.get("detail", {})
    status = detail.get("NotebookInstanceStatus")
    if status not in ("Stopped", "InService"):
        logger.info("Ignoring state-change event with status %s", status)
        return
    name = detail.get("NotebookInstanceName")
    if not name:
        logger.warning("No NotebookInstanceName in state-change event, skipping")
        return
    if status == "InService":
        # Catches a notebook first seen while Pending, and a restart of one
        # still awaiting recreation.
        _flag_and_stop(name)
        return
    _finish_remediation(name)


def _handle_direct_invocation(event):
    name = event.get("notebook_instance_name") or event.get("NotebookInstanceName")
    if not name:
        logger.warning("No notebook_instance_name provided in direct invocation event")
        return {"remediated": False, "reason": "no notebook instance name provided"}
    # Accept either a plain name or a full ARN (Config's RESOURCE_ID
    # convention for this resource type isn't consistently documented) -
    # extract the name from an ARN if one was passed instead.
    if name.startswith("arn:") and ":notebook-instance/" in name:
        name = name.rsplit(":notebook-instance/", 1)[-1]
    _flag_and_stop(name)
    return {"remediated": True}


def lambda_handler(event, context):
    logger.info("Event: %s", json.dumps(event, default=str))

    detail_type = event.get("detail-type")
    detail = event.get("detail", {}) or {}

    if detail_type == "AWS API Call via CloudTrail" and detail.get("eventName") in (
        "CreateNotebookInstance",
        "UpdateNotebookInstance",
    ):
        _handle_cloudtrail_event(event)
        return {"statusCode": 200}

    if detail_type == "SageMaker Notebook Instance State Change":
        _handle_state_change_event(event)
        return {"statusCode": 200}

    result = _handle_direct_invocation(event)
    return {"statusCode": 200, "body": json.dumps(result, default=str)}
