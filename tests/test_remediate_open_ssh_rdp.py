import json
from unittest.mock import MagicMock

import pytest

LAMBDA = "terraform/auto-remediate-open-ssh-rdp/lambda/remediate_open_ssh_rdp.py"


@pytest.fixture
def fn(load_lambda):
    module = load_lambda(LAMBDA, SNS_TOPIC_ARN="arn:aws:sns:us-east-1:123456789012:alerts")
    module.ec2 = MagicMock()
    module.sns = MagicMock()
    return module


def _authorize_event(group_id, *items):
    return {
        "detail-type": "AWS API Call via CloudTrail",
        "detail": {
            "eventName": "AuthorizeSecurityGroupIngress",
            "requestParameters": {"groupId": group_id, "ipPermissions": {"items": list(items)}},
            "responseElements": {"_return": True},
        },
    }


def _item(protocol, from_port, to_port, v4=(), v6=()):
    return {
        "ipProtocol": protocol,
        "fromPort": from_port,
        "toPort": to_port,
        "ipRanges": {"items": [{"cidrIp": c} for c in v4]},
        "ipv6Ranges": {"items": [{"cidrIpv6": c} for c in v6]},
    }


def _group(*permissions):
    return {"SecurityGroups": [{"IpPermissions": list(permissions)}]}


def _revoked(fn):
    return [c.kwargs["IpPermissions"][0] for c in fn.ec2.revoke_security_group_ingress.call_args_list]


def test_revokes_only_the_internet_cidr_on_ssh(fn):
    fn.lambda_handler(_authorize_event("sg-1", _item("tcp", 22, 22, v4=["0.0.0.0/0", "10.0.0.0/8"])), None)

    assert _revoked(fn) == [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    fn.sns.publish.assert_called_once()


def test_revokes_ipv6_rdp(fn):
    fn.lambda_handler(_authorize_event("sg-1", _item("tcp", 3389, 3389, v6=["::/0"])), None)

    assert _revoked(fn)[0]["Ipv6Ranges"] == [{"CidrIpv6": "::/0"}]


def test_port_range_covering_ssh_is_revoked(fn):
    fn.lambda_handler(_authorize_event("sg-1", _item("tcp", 0, 1024, v4=["0.0.0.0/0"])), None)

    assert len(_revoked(fn)) == 1


def test_all_traffic_rule_is_revoked_without_ports(fn):
    fn.lambda_handler(_authorize_event("sg-1", _item("-1", None, None, v4=["0.0.0.0/0"])), None)

    revoked = _revoked(fn)[0]
    assert revoked["IpProtocol"] == "-1"
    assert "FromPort" not in revoked and "ToPort" not in revoked


def test_https_to_the_internet_is_left_alone(fn):
    fn.lambda_handler(_authorize_event("sg-1", _item("tcp", 443, 443, v4=["0.0.0.0/0"])), None)

    fn.ec2.revoke_security_group_ingress.assert_not_called()
    fn.sns.publish.assert_not_called()


def test_ssh_from_a_private_range_is_left_alone(fn):
    fn.lambda_handler(_authorize_event("sg-1", _item("tcp", 22, 22, v4=["10.0.0.0/8"])), None)

    fn.ec2.revoke_security_group_ingress.assert_not_called()


def test_modify_event_rescans_the_group_from_the_wrapped_request(fn):
    # CloudTrail records ModifySecurityGroupRules with its request wrapped in
    # ModifySecurityGroupRulesRequest, not a flat groupId.
    fn.ec2.describe_security_groups.return_value = _group(
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    )
    event = {
        "detail-type": "AWS API Call via CloudTrail",
        "detail": {
            "eventName": "ModifySecurityGroupRules",
            "requestParameters": {
                "ModifySecurityGroupRulesRequest": {
                    "GroupId": "sg-2",
                    "SecurityGroupRule": {"SecurityGroupRuleId": "sgr-1"},
                }
            },
        },
    }

    fn.lambda_handler(event, None)

    fn.ec2.describe_security_groups.assert_called_once_with(GroupIds=["sg-2"])
    assert len(_revoked(fn)) == 1


def test_direct_invocation_from_config_remediation(fn):
    fn.ec2.describe_security_groups.return_value = _group(
        {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    )

    result = fn.lambda_handler({"security_group_id": "sg-3"}, None)

    assert json.loads(result["body"])["remediated"] is True


def test_missing_group_is_reported_not_raised(fn):
    fn.ec2.describe_security_groups.return_value = {"SecurityGroups": []}

    result = fn.lambda_handler({"security_group_id": "sg-gone"}, None)

    assert json.loads(result["body"])["reason"] == "security group not found"
