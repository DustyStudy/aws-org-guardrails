"""
Scans every IAM role's trust policy for AI/agent service principals
(Bedrock, SageMaker, Amazon Q, etc.) and, separately, discovers the
Lambda execution roles behind every Bedrock Agent's action groups - and
for any matching role, checks its attached and inline policies for
overly-broad grants: full admin, a service-wide wildcard on a sensitive
service combined with Resource "*", or the AdministratorAccess managed
policy. Publishes a summary to SNS. Detective only - no remediation,
since automatically stripping a role's permissions could break its
intended function; a human should review and right-size these roles
deliberately.

The risk this targets: agentic AI workflows often get built by handing
broad permissions "to get it working," since the workload may need to
call many different APIs depending on what task it's given. That's a
much larger blast radius than a human operator with the same role,
because the agent can be steered (via prompt injection or just bad task
design) into calling any API the role permits, at machine speed, without
a human in the loop to notice something's wrong.

Two distinct discovery paths, because they catch different roles:

1. Trust-policy scan: any IAM role whose trust policy names an AI/agent
   service principal directly (the role Bedrock/SageMaker/Q itself
   assumes to run inference or manage a resource).
2. Bedrock Agent action-group scan: a Bedrock Agent's *own* role is often
   fairly narrow, but each action group hands real execution off to a
   separate Lambda function - and that Lambda's execution role is
   trusted by lambda.amazonaws.com, not Bedrock, so it's invisible to
   the trust-policy scan even though it's what actually runs when the
   agent decides to act. This is usually the higher-risk role of the two.
   Only the DRAFT version of each agent's action groups is checked - a
   known scope limitation, see the README.

Env vars:
  SNS_TOPIC_ARN               - where to send the audit summary
  AI_SERVICE_PRINCIPALS       - comma-separated list of trust-policy
                                service principals to treat as "AI/agent"
                                roles (default covers Bedrock, SageMaker,
                                Amazon Q)
  SENSITIVE_WILDCARD_SERVICES - comma-separated list of IAM service
                                prefixes where "<service>:*" + Resource "*"
                                is flagged (default: iam, ec2, s3, kms,
                                organizations, sts)
  CHECK_BEDROCK_AGENT_ACTION_GROUPS - "true"/"false" - enable the Bedrock
                                Agent action-group Lambda discovery path
                                (default "true")
"""

import os
import json
import logging

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

iam = boto3.client("iam")
sns = boto3.client("sns")
lambda_client = boto3.client("lambda")
bedrock_agent = boto3.client("bedrock-agent")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
AI_SERVICE_PRINCIPALS = [
    s.strip()
    for s in os.environ.get(
        "AI_SERVICE_PRINCIPALS",
        "bedrock.amazonaws.com,sagemaker.amazonaws.com,q.amazonaws.com,qbusiness.amazonaws.com",
    ).split(",")
    if s.strip()
]
SENSITIVE_WILDCARD_SERVICES = [
    s.strip()
    for s in os.environ.get("SENSITIVE_WILDCARD_SERVICES", "iam,ec2,s3,kms,organizations,sts").split(",")
    if s.strip()
]
CHECK_BEDROCK_AGENT_ACTION_GROUPS = os.environ.get("CHECK_BEDROCK_AGENT_ACTION_GROUPS", "true").lower() == "true"
ADMIN_POLICY_ARN_SUFFIX = "/AdministratorAccess"


def _notify(subject, message):
    if not SNS_TOPIC_ARN:
        logger.info("SNS_TOPIC_ARN not set, skipping notification")
        return
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject[:100], Message=message)
    except ClientError:
        logger.exception("Failed to publish SNS notification")


def _principals_from_trust_policy(trust_policy):
    services = set()
    # "Statement" may be a single object rather than a list - both are valid IAM.
    for statement in _as_list(trust_policy.get("Statement")):
        if not isinstance(statement, dict):
            continue
        principal = statement.get("Principal", {})
        if not isinstance(principal, dict):
            continue
        svc = principal.get("Service")
        if svc is None:
            continue
        if isinstance(svc, str):
            services.add(svc)
        elif isinstance(svc, list):
            services.update(svc)
    return services


def _matching_ai_principals(trust_policy):
    services = _principals_from_trust_policy(trust_policy)
    return services.intersection(AI_SERVICE_PRINCIPALS)


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _statement_is_risky(statement):
    if statement.get("Effect") != "Allow":
        return None

    actions = [a.lower() for a in _as_list(statement.get("Action"))]
    resources = _as_list(statement.get("Resource"))
    has_wildcard_resource = "*" in resources

    if "*" in actions:
        return "full wildcard action ('*')"

    # Allow + NotAction grants every action *except* the listed ones, which
    # on Resource "*" is effectively near-admin access.
    if statement.get("NotAction") is not None and has_wildcard_resource:
        return "Allow with NotAction on Resource '*' (grants everything except the listed actions)"

    if has_wildcard_resource:
        for action in actions:
            if ":" not in action:
                continue
            service, _, rest = action.partition(":")
            if rest == "*" and service in SENSITIVE_WILDCARD_SERVICES:
                return f"service-wide wildcard action ({action}) with Resource '*'"

    return None


def _evaluate_policy_document(doc, source_label, findings):
    # "Statement" may be a single object rather than a list - both are valid
    # IAM, and iterating a dict here would silently skip the whole policy.
    for statement in _as_list(doc.get("Statement")):
        if isinstance(statement, dict):
            reason = _statement_is_risky(statement)
            if reason:
                findings.append({"source": source_label, "sid": statement.get("Sid", "(no Sid)"), "reason": reason})


def _evaluate_role(role_name):
    findings = []

    try:
        attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
    except ClientError:
        logger.exception("Failed to list attached policies for role %s", role_name)
        attached = []

    for policy in attached:
        if policy.get("PolicyArn", "").endswith(ADMIN_POLICY_ARN_SUFFIX):
            findings.append(
                {"source": f"managed policy {policy['PolicyName']}", "sid": "(whole policy)", "reason": "AdministratorAccess attached"}
            )
            continue
        try:
            policy_arn = policy["PolicyArn"]
            version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)["PolicyVersion"]["Document"]
            _evaluate_policy_document(doc, f"managed policy {policy['PolicyName']}", findings)
        except ClientError:
            logger.exception("Failed to evaluate managed policy %s for role %s", policy.get("PolicyName"), role_name)

    try:
        inline_names = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
    except ClientError:
        logger.exception("Failed to list inline policies for role %s", role_name)
        inline_names = []

    for name in inline_names:
        try:
            doc = iam.get_role_policy(RoleName=role_name, PolicyName=name)["PolicyDocument"]
            _evaluate_policy_document(doc, f"inline policy {name}", findings)
        except ClientError:
            logger.exception("Failed to evaluate inline policy %s for role %s", name, role_name)

    return findings


def _iter_roles():
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page.get("Roles", []):
            yield role


def _iter_bedrock_agents():
    try:
        paginator = bedrock_agent.get_paginator("list_agents")
        for page in paginator.paginate():
            for agent in page.get("agentSummaries", []):
                yield agent
    except ClientError:
        logger.exception("Failed to list Bedrock Agents")


def _iter_action_group_lambda_arns(agent_id):
    """Yields (action_group_name, lambda_arn) for every action group on an
    agent's DRAFT version that's backed by a Lambda executor. Action
    groups can also use return-of-control (no Lambda) or the built-in
    code interpreter, which are skipped since there's no execution role
    to audit."""
    try:
        paginator = bedrock_agent.get_paginator("list_agent_action_groups")
        for page in paginator.paginate(agentId=agent_id, agentVersion="DRAFT"):
            for summary in page.get("actionGroupSummaries", []):
                action_group_id = summary["actionGroupId"]
                try:
                    detail = bedrock_agent.get_agent_action_group(
                        agentId=agent_id, agentVersion="DRAFT", actionGroupId=action_group_id
                    )["agentActionGroup"]
                except ClientError:
                    logger.exception("Failed to get action group %s for agent %s", action_group_id, agent_id)
                    continue
                executor = detail.get("actionGroupExecutor", {})
                lambda_arn = executor.get("lambda")
                if lambda_arn:
                    yield summary.get("actionGroupName", action_group_id), lambda_arn
    except ClientError:
        logger.exception("Failed to list action groups for agent %s", agent_id)


def _role_name_from_lambda_arn(lambda_arn):
    try:
        role_arn = lambda_client.get_function(FunctionName=lambda_arn)["Configuration"]["Role"]
    except ClientError:
        logger.exception("Failed to get function configuration for %s", lambda_arn)
        return None
    # arn:partition:iam::account:role/name (or role/path/name)
    return role_arn.rsplit("/", 1)[-1]


def _iter_bedrock_agent_action_group_roles():
    """Yields (role_name, context_label) for every Lambda execution role
    backing a Bedrock Agent action group. This is usually the
    higher-risk role of the two discovery paths, since it's what
    actually executes when the agent decides to act - and it's invisible
    to the trust-policy scan because its own trust policy names
    lambda.amazonaws.com, not Bedrock."""
    if not CHECK_BEDROCK_AGENT_ACTION_GROUPS:
        return
    for agent in _iter_bedrock_agents():
        agent_id = agent["agentId"]
        agent_name = agent.get("agentName", agent_id)
        for action_group_name, lambda_arn in _iter_action_group_lambda_arns(agent_id):
            role_name = _role_name_from_lambda_arn(lambda_arn)
            if role_name:
                yield role_name, f"Bedrock Agent '{agent_name}' action group '{action_group_name}' (via {lambda_arn})"


def lambda_handler(event, context):
    logger.info("Starting AI/agent IAM privilege audit")
    flagged_roles = []
    seen_role_names = set()

    for role in _iter_roles():
        role_name = role["RoleName"]
        trust_policy = role.get("AssumeRolePolicyDocument", {})
        matched_principals = _matching_ai_principals(trust_policy)
        if not matched_principals:
            continue

        findings = _evaluate_role(role_name)
        if findings:
            seen_role_names.add(role_name)
            flagged_roles.append(
                {
                    "role_name": role_name,
                    "role_arn": role.get("Arn"),
                    "context": f"Trusted by: {', '.join(sorted(matched_principals))}",
                    "findings": findings,
                }
            )

    for role_name, context in _iter_bedrock_agent_action_group_roles():
        if role_name in seen_role_names:
            continue  # already flagged via the trust-policy path
        findings = _evaluate_role(role_name)
        if findings:
            seen_role_names.add(role_name)
            try:
                role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
            except ClientError:
                role_arn = "(unknown)"
            flagged_roles.append(
                {
                    "role_name": role_name,
                    "role_arn": role_arn,
                    "context": context,
                    "findings": findings,
                }
            )

    if flagged_roles:
        lines = []
        for r in flagged_roles:
            lines.append(f"\nRole: {r['role_name']} ({r['role_arn']})")
            lines.append(f"  {r['context']}")
            for f in r["findings"]:
                lines.append(f"  - [{f['source']}] {f['sid']}: {f['reason']}")

        _notify(
            subject=f"AI agent IAM audit: {len(flagged_roles)} over-permissioned role(s) found",
            message=(
                "The following IAM roles are trusted by an AI/agent service, or "
                "execute a Bedrock Agent action group, and carry broader "
                "permissions than typically necessary. Review and "
                "right-size these deliberately - this audit does not "
                "modify anything.\n" + "\n".join(lines)
            ),
        )
    else:
        logger.info("No over-permissioned AI/agent roles found")

    return {
        "statusCode": 200,
        "body": json.dumps({"flagged_role_count": len(flagged_roles), "flagged_roles": [r["role_name"] for r in flagged_roles]}),
    }
