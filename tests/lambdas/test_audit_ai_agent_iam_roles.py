import json
from unittest.mock import MagicMock

import pytest

LAMBDA = "modules/ai-agent-iam-auditor/lambda/audit_ai_agent_iam_roles.py"


def _trust(*services):
    return {"Statement": [{"Effect": "Allow", "Principal": {"Service": list(services)}, "Action": "sts:AssumeRole"}]}


def _role(name, *services):
    return {
        "RoleName": name,
        "Arn": f"arn:aws:iam::123456789012:role/{name}",
        "AssumeRolePolicyDocument": _trust(*services),
    }


@pytest.fixture
def make_fn(load_lambda):
    def _make(roles, attached=None, inline=None, agents=(), **env):
        module = load_lambda(LAMBDA, SNS_TOPIC_ARN="arn:aws:sns:us-east-1:123456789012:alerts", **env)
        attached, inline = attached or {}, inline or {}
        iam = MagicMock()
        iam.get_paginator.return_value.paginate.return_value = [{"Roles": roles}]
        iam.list_attached_role_policies.side_effect = lambda RoleName: {"AttachedPolicies": attached.get(RoleName, [])}
        iam.list_role_policies.side_effect = lambda RoleName: {"PolicyNames": list(inline.get(RoleName, {}))}
        iam.get_role_policy.side_effect = lambda RoleName, PolicyName: {"PolicyDocument": inline[RoleName][PolicyName]}
        iam.get_role.side_effect = lambda RoleName: {"Role": {"Arn": f"arn:aws:iam::123456789012:role/{RoleName}"}}

        bedrock_agent = MagicMock()
        paginators = {
            "list_agents": [{"agentSummaries": [{"agentId": a["id"], "agentName": a["id"]} for a in agents]}],
        }
        groups = {a["id"]: a["groups"] for a in agents}

        def get_paginator(name):
            paginator = MagicMock()
            if name == "list_agents":
                paginator.paginate.return_value = paginators["list_agents"]
            else:
                paginator.paginate.side_effect = lambda agentId, agentVersion: [
                    {"actionGroupSummaries": [{"actionGroupId": g, "actionGroupName": g} for g in groups[agentId]]}
                ]
            return paginator

        bedrock_agent.get_paginator.side_effect = get_paginator
        bedrock_agent.get_agent_action_group.side_effect = lambda agentId, agentVersion, actionGroupId: {
            "agentActionGroup": {"actionGroupExecutor": groups[agentId][actionGroupId]}
        }
        lambda_client = MagicMock()
        lambda_client.get_function.side_effect = lambda FunctionName: {
            "Configuration": {"Role": f"arn:aws:iam::123456789012:role/{FunctionName.rsplit(':', 1)[-1]}-role"}
        }
        module.iam, module.bedrock_agent, module.lambda_client, module.sns = (
            iam,
            bedrock_agent,
            lambda_client,
            MagicMock(),
        )
        return module

    return _make


def _flagged(fn):
    return json.loads(fn.lambda_handler({}, None)["body"])["flagged_roles"]


def test_bedrock_role_with_admin_is_flagged(make_fn):
    fn = make_fn(
        [_role("agent", "bedrock.amazonaws.com")],
        attached={
            "agent": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]
        },
    )

    assert _flagged(fn) == ["agent"]
    assert "AdministratorAccess attached" in fn.sns.publish.call_args.kwargs["Message"]


def test_non_ai_role_is_ignored_even_if_admin(make_fn):
    fn = make_fn(
        [_role("ci", "codebuild.amazonaws.com")],
        attached={
            "ci": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]
        },
    )

    assert _flagged(fn) == []
    fn.sns.publish.assert_not_called()


def test_single_statement_object_is_evaluated(make_fn):
    fn = make_fn(
        [_role("nb", "sagemaker.amazonaws.com")],
        inline={"nb": {"wide": {"Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}}}},
    )

    assert _flagged(fn) == ["nb"]


def test_scoped_role_is_not_flagged(make_fn):
    fn = make_fn(
        [_role("nb", "sagemaker.amazonaws.com")],
        inline={
            "nb": {
                "ok": {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::data/*"}]}
            }
        },
    )

    assert _flagged(fn) == []


def test_action_group_lambda_role_is_found_and_flagged(make_fn):
    fn = make_fn(
        [],
        inline={"tool-role": {"p": {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}}},
        agents=[{"id": "a1", "groups": {"g1": {"lambda": "arn:aws:lambda:us-east-1:123456789012:function:tool"}}}],
    )

    assert _flagged(fn) == ["tool-role"]
    assert "action group 'g1'" in fn.sns.publish.call_args.kwargs["Message"]


def test_return_of_control_action_groups_are_skipped(make_fn):
    fn = make_fn([], agents=[{"id": "a1", "groups": {"g1": {"customControl": "RETURN_CONTROL"}}}])

    assert _flagged(fn) == []
    fn.lambda_client.get_function.assert_not_called()


def test_action_group_scan_can_be_disabled(make_fn):
    fn = make_fn(
        [],
        agents=[{"id": "a1", "groups": {"g1": {"lambda": "arn:aws:lambda:us-east-1:123456789012:function:tool"}}}],
        CHECK_BEDROCK_AGENT_ACTION_GROUPS="false",
    )

    fn.lambda_handler({}, None)

    fn.bedrock_agent.get_paginator.assert_not_called()


def test_role_found_both_ways_is_reported_once(make_fn):
    fn = make_fn(
        [_role("tool-role", "bedrock.amazonaws.com")],
        inline={"tool-role": {"p": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}},
        agents=[{"id": "a1", "groups": {"g1": {"lambda": "arn:aws:lambda:us-east-1:123456789012:function:tool"}}}],
    )

    assert _flagged(fn) == ["tool-role"]
