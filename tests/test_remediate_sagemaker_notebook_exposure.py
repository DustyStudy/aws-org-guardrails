from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

LAMBDA = "terraform/sagemaker-notebook-exposure/lambda/remediate_sagemaker_notebook_exposure.py"
ARN = "arn:aws:sagemaker:us-east-1:123456789012:notebook-instance/nb1"


def _description(status="InService", internet="Enabled", root="Disabled"):
    return {
        "NotebookInstanceArn": ARN,
        "NotebookInstanceStatus": status,
        "DirectInternetAccess": internet,
        "RootAccess": root,
    }


@pytest.fixture
def make_fn(load_lambda):
    def _make(description, pending=False, **env):
        module = load_lambda(LAMBDA, SNS_TOPIC_ARN="arn:aws:sns:us-east-1:123456789012:alerts", **env)
        sagemaker = MagicMock()
        sagemaker.describe_notebook_instance.return_value = description
        tags = [{"Key": "sagemaker-remediation-pending", "Value": "true"}] if pending else []
        sagemaker.list_tags.return_value = {"Tags": tags}
        module.sagemaker, module.sns = sagemaker, MagicMock()
        return module

    return _make


def _cloudtrail_event(name="nb1"):
    return {
        "detail-type": "AWS API Call via CloudTrail",
        "detail": {"eventName": "CreateNotebookInstance", "requestParameters": {"notebookInstanceName": name}},
    }


def _stopped_event(name="nb1"):
    return {
        "detail-type": "SageMaker Notebook Instance State Change",
        "detail": {"NotebookInstanceStatus": "Stopped", "NotebookInstanceName": name},
    }


def test_running_exposed_notebook_is_tagged_and_stopped(make_fn):
    fn = make_fn(_description())

    fn.lambda_handler(_cloudtrail_event(), None)

    fn.sagemaker.add_tags.assert_called_once()
    fn.sagemaker.stop_notebook_instance.assert_called_once_with(NotebookInstanceName="nb1")
    fn.sagemaker.update_notebook_instance.assert_not_called()


def test_compliant_notebook_is_left_alone(make_fn):
    fn = make_fn(_description(internet="Disabled"))

    fn.lambda_handler(_cloudtrail_event(), None)

    fn.sagemaker.add_tags.assert_not_called()
    fn.sagemaker.stop_notebook_instance.assert_not_called()


def test_stop_event_finishes_remediation_and_leaves_it_stopped(make_fn):
    fn = make_fn(_description(status="Stopped", root="Enabled"), pending=True)

    fn.lambda_handler(_stopped_event(), None)

    fn.sagemaker.update_notebook_instance.assert_called_once_with(
        NotebookInstanceName="nb1", DirectInternetAccess="Disabled", RootAccess="Disabled"
    )
    fn.sagemaker.delete_tags.assert_called_once()
    fn.sagemaker.start_notebook_instance.assert_not_called()


def test_auto_restart_starts_it_again(make_fn):
    fn = make_fn(_description(status="Stopped"), pending=True, AUTO_RESTART="true")

    fn.lambda_handler(_stopped_event(), None)

    fn.sagemaker.start_notebook_instance.assert_called_once_with(NotebookInstanceName="nb1")


def test_stop_event_without_pending_tag_does_nothing(make_fn):
    fn = make_fn(_description(status="Stopped"))

    fn.lambda_handler(_stopped_event(), None)

    fn.sagemaker.update_notebook_instance.assert_not_called()


def test_already_stopped_notebook_is_fixed_in_one_pass(make_fn):
    fn = make_fn(_description(status="Stopped"))
    fn.sagemaker.list_tags.side_effect = lambda ResourceArn: {
        "Tags": [{"Key": "sagemaker-remediation-pending", "Value": "true"}]
    }

    fn.lambda_handler({"notebook_instance_name": ARN}, None)

    fn.sagemaker.describe_notebook_instance.assert_called_with(NotebookInstanceName="nb1")
    fn.sagemaker.update_notebook_instance.assert_called_once()


def test_failed_update_keeps_the_tag_and_notifies(make_fn):
    fn = make_fn(_description(status="Stopped"), pending=True)
    fn.sagemaker.update_notebook_instance.side_effect = ClientError(
        {"Error": {"Code": "ValidationException", "Message": "no subnet"}}, "UpdateNotebookInstance"
    )

    fn.lambda_handler(_stopped_event(), None)

    fn.sagemaker.delete_tags.assert_not_called()
    assert "FAILED" in fn.sns.publish.call_args.kwargs["Subject"]


def test_non_stopped_state_change_is_ignored(make_fn):
    fn = make_fn(_description())

    fn.lambda_handler(
        {"detail-type": "SageMaker Notebook Instance State Change", "detail": {"NotebookInstanceStatus": "Stopping"}},
        None,
    )

    fn.sagemaker.describe_notebook_instance.assert_not_called()
