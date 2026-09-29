"""
Auto-revoke security group ingress rules that open SSH (22) or RDP (3389)
to the entire internet (0.0.0.0/0 or ::/0).

Handles two invocation styles so the same function can be reused by both
the event-driven (EventBridge + CloudTrail) and AWS Config + SSM
Automation remediation paths:

1. EventBridge rule matching CloudTrail's AuthorizeSecurityGroupIngress
   management event. Revokes only the specific rule(s) just added. A
   ModifySecurityGroupRules event (an existing rule edited to be open) is
   also handled, but its request is rule-ID based rather than describing the
   resulting CIDR, so the whole group is re-scanned instead.
2. Direct invocation with {"security_group_id": "sg-xxxxxxxx"} (used by
   the SSM Automation document triggered from an AWS Config remediation).
   Describes the group and revokes any matching bad rules found on it
   (covers drift / rules added outside the event path, e.g. before this
   stack was deployed, or via Terraform directly).

Works in both AWS commercial and GovCloud partitions - no partition-
specific values are hardcoded here; boto3 resolves the correct endpoints
and the caller's IAM policy handles the ARN partition.
"""

import os
import json
import logging

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

ec2 = boto3.client("ec2")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
RISKY_PORTS = {22, 3389}
RISKY_CIDR_V4 = "0.0.0.0/0"
RISKY_CIDR_V6 = "::/0"


def _port_range_overlaps_risky(protocol, from_port, to_port):
    """Return True if the given port range includes 22 or 3389, or if the
    rule has no port restriction at all (protocol -1 / from-to missing)."""
    if str(protocol) == "-1" or from_port is None or to_port is None:
        return True
    for port in RISKY_PORTS:
        if from_port <= port <= to_port:
            return True
    return False


def _notify(subject, message):
    if not SNS_TOPIC_ARN:
        logger.info("SNS_TOPIC_ARN not set, skipping notification")
        return
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject[:100], Message=message)
    except ClientError:
        logger.exception("Failed to publish SNS notification")


def _revoke_from_permissions(group_id, ip_permissions, source):
    """Given a list of IpPermissions (flat AWS API shape), find and revoke
    any entries that open SSH/RDP to the internet. Returns the list of
    rules actually revoked."""
    revoked = []
    for perm in ip_permissions:
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")
        if not _port_range_overlaps_risky(perm.get("IpProtocol"), from_port, to_port):
            continue

        bad_v4 = [r for r in perm.get("IpRanges", []) if r.get("CidrIp") == RISKY_CIDR_V4]
        bad_v6 = [r for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == RISKY_CIDR_V6]

        if not bad_v4 and not bad_v6:
            continue

        revoke_perm = {"IpProtocol": perm.get("IpProtocol", "tcp")}
        # An all-traffic rule (IpProtocol "-1") has no ports; passing
        # FromPort/ToPort as None would fail boto3 parameter validation.
        if str(revoke_perm["IpProtocol"]) != "-1":
            if from_port is not None:
                revoke_perm["FromPort"] = from_port
            if to_port is not None:
                revoke_perm["ToPort"] = to_port
        if bad_v4:
            revoke_perm["IpRanges"] = bad_v4
        if bad_v6:
            revoke_perm["Ipv6Ranges"] = bad_v6

        try:
            ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=[revoke_perm])
            revoked.append(revoke_perm)
            logger.info("Revoked risky ingress on %s: %s", group_id, revoke_perm)
        except ClientError:
            logger.exception("Failed to revoke ingress on %s", group_id)

    if revoked:
        _notify(
            subject=f"Revoked open SSH/RDP on {group_id}"[:100],
            message=(
                f"Source: {source}\n"
                f"Security Group: {group_id}\n"
                f"Revoked rule(s):\n{json.dumps(revoked, indent=2, default=str)}"
            ),
        )
    return revoked


def _extract_ip_permissions(container):
    """CloudTrail's requestParameters/responseElements nest permissions as
    ipPermissions.items[].ipRanges.items[] with lowerCamelCase keys.
    Normalize into the flat AWS API shape used by revoke_security_group_ingress."""
    ip_perms_container = (container or {}).get("ipPermissions")
    if not ip_perms_container:
        return []

    normalized = []
    for item in ip_perms_container.get("items", []):
        normalized.append(
            {
                "IpProtocol": item.get("ipProtocol"),
                "FromPort": item.get("fromPort"),
                "ToPort": item.get("toPort"),
                "IpRanges": [
                    {"CidrIp": r.get("cidrIp")}
                    for r in (item.get("ipRanges", {}) or {}).get("items", [])
                ],
                "Ipv6Ranges": [
                    {"CidrIpv6": r.get("cidrIpv6")}
                    for r in (item.get("ipv6Ranges", {}) or {}).get("items", [])
                ],
            }
        )
    return normalized


def _revoke_from_group(group_id, source):
    """Describe a security group and revoke any SSH/RDP-to-the-internet
    rules currently on it. Returns a small result dict."""
    resp = ec2.describe_security_groups(GroupIds=[group_id])
    groups = resp.get("SecurityGroups", [])
    if not groups:
        logger.warning("Security group %s not found", group_id)
        return {"remediated": False, "reason": "security group not found"}

    ip_permissions = groups[0].get("IpPermissions", [])
    revoked = _revoke_from_permissions(group_id, ip_permissions, source=source)
    return {"remediated": bool(revoked), "revoked_rules": revoked}


def _handle_cloudtrail_event(event):
    detail = event.get("detail", {})
    request_params = detail.get("requestParameters", {}) or {}
    # AuthorizeSecurityGroupIngress records a flat lowerCamelCase groupId.
    # ModifySecurityGroupRules wraps its request instead:
    # requestParameters.ModifySecurityGroupRulesRequest.GroupId.
    modify_request = request_params.get("ModifySecurityGroupRulesRequest") or {}
    group_id = request_params.get("groupId") or modify_request.get("GroupId")
    if not group_id:
        logger.warning("No groupId found in CloudTrail event detail, skipping")
        return

    if detail.get("eventName") == "ModifySecurityGroupRules":
        _revoke_from_group(group_id, source="cloudtrail-eventbridge-modify")
        return

    response_elements = detail.get("responseElements", {}) or {}
    ip_permissions = _extract_ip_permissions(response_elements) or _extract_ip_permissions(request_params)

    if not ip_permissions:
        logger.warning("Could not extract IpPermissions from event for %s", group_id)
        return

    _revoke_from_permissions(group_id, ip_permissions, source="cloudtrail-eventbridge")


def _handle_direct_invocation(event):
    group_id = event.get("security_group_id") or event.get("SecurityGroupId") or event.get("resourceId")
    if not group_id:
        logger.warning("No security_group_id provided in direct invocation event")
        return {"remediated": False, "reason": "no security group id provided"}

    return _revoke_from_group(group_id, source="config-ssm-remediation")


def lambda_handler(event, context):
    logger.info("Event: %s", json.dumps(event, default=str))

    handled_events = ("AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules")
    is_cloudtrail_event = event.get("detail-type") == "AWS API Call via CloudTrail" or (
        "detail" in event and event.get("detail", {}).get("eventName") in handled_events
    )

    if is_cloudtrail_event:
        _handle_cloudtrail_event(event)
        return {"statusCode": 200}

    result = _handle_direct_invocation(event)
    return {"statusCode": 200, "body": json.dumps(result, default=str)}
