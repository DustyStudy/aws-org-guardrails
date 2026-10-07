"""Probe the AI/ML SCPs, the newer baseline statements and the identity-center module.

Same rules as ../probe.py: a probe must change nothing when the guardrail
works and as little as possible when it does not.

* SageMaker resolves the execution role and the KMS key before it checks
  authorization, so both must be real: the script creates a role with no
  permissions beyond kms:DescribeKey and a KMS key, and removes them at the
  end. The subnet does not exist, so the one notebook request that the
  guardrails allow creates a notebook that fails to start, and that
  notebook is then used to probe UpdateNotebookInstance and deleted. The
  allowed training job stops at the account's instance quota, or is
  stopped by the script if it starts.
* Bedrock invocations are valid requests of a few tokens. Some models
  validate the body before Bedrock checks authorization, so an empty body
  cannot show that a request was allowed. The two allowed invocations cost
  a fraction of a cent.
* The two IAM-user guardrails need an IAM user. The exempt break-glass role
  creates one with an access key that lives only in this process, and
  deletes both at the end.
* AWS RAM probes create empty resource shares and delete them.

The Identity Center half reads the permission set back from the service,
then signs in with it (using the cached IAM Identity Center token of the
assigned user) and probes the permissions boundary and the inline policy.

Usage:
    terraform -chdir=proof/run2 output -json > outputs.json
    python proof/run2/probe.py --profile <sandbox-admin-profile> \\
        --management-profile <management-profile> --outputs outputs.json
Writes Markdown tables to stdout with account IDs replaced by 111122223333.
Exits 1 if any probe differs from its expectation.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import sys
import time
from collections.abc import Callable
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from probe import BOUNDARY, IDENTITY, NOT_DENIED, PROBE, SCP, UNNAMED_DENY, Probe, assume, classify

USER = f"{PROBE}-user"
ROLE = f"{PROBE}-sagemaker"
MISSING = "0123456789abcdef0"


def build_probes(partition: str, account_id: str, role_arn: str, key_arn: str, shares: dict[str, str]) -> list[Probe]:
    bedrock = lambda s: s.client("bedrock")  # noqa: E731
    sagemaker = lambda s: s.client("sagemaker")  # noqa: E731
    ram = lambda s: s.client("ram")  # noqa: E731

    def converse(model_id: str) -> Callable[[boto3.Session], object]:
        return lambda s: s.client("bedrock-runtime").converse(
            modelId=model_id,
            messages=[{"role": "user", "content": [{"text": "Reply with the word ok"}]}],
            inferenceConfig={"maxTokens": 5},
        )

    def embed(s: boto3.Session) -> object:
        return s.client("bedrock-runtime").invoke_model(
            modelId="amazon.titan-embed-text-v2:0", body=json.dumps({"inputText": "ok"})
        )

    def notebook(**overrides: object) -> Callable[[boto3.Session], object]:
        request = {
            "NotebookInstanceName": PROBE,
            "InstanceType": "ml.t3.medium",
            "RoleArn": role_arn,
            "SubnetId": f"subnet-{MISSING}",
            "SecurityGroupIds": [f"sg-{MISSING}"],
            "KmsKeyId": key_arn,
            "DirectInternetAccess": "Disabled",
            "RootAccess": "Disabled",
        } | overrides
        request = {k: v for k, v in request.items() if v is not None}
        return lambda s: sagemaker(s).create_notebook_instance(**request)

    def training_job(volume_key: bool = True, output_key: bool = True) -> Callable[[boto3.Session], object]:
        key = {"KmsKeyId": key_arn} if output_key else {}
        volume = {"VolumeKmsKeyId": key_arn} if volume_key else {}
        return lambda s: sagemaker(s).create_training_job(
            TrainingJobName=PROBE,
            AlgorithmSpecification={
                "TrainingImage": f"{account_id}.dkr.ecr.us-east-1.amazonaws.com/{PROBE}:latest",
                "TrainingInputMode": "File",
            },
            RoleArn=role_arn,
            OutputDataConfig={"S3OutputPath": f"s3://{PROBE}-missing/out", **key},
            ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 1, **volume},
            StoppingCondition={"MaxRuntimeInSeconds": 60},
        )

    def share(name: str, external: bool) -> Callable[[boto3.Session], object]:
        def call(s: boto3.Session) -> None:
            created = ram(s).create_resource_share(name=f"{PROBE}-{name}", allowExternalPrincipals=external)
            shares[name] = created["resourceShare"]["resourceShareArn"]

        return call

    return [
        # --- Bedrock logging and guardrails (these SCPs exempt nobody)
        Probe(
            "workload",
            "bedrock:DeleteModelInvocationLoggingConfiguration",
            SCP,
            lambda s: bedrock(s).delete_model_invocation_logging_configuration(),
        ),
        Probe(
            "workload",
            "bedrock:DeleteGuardrail",
            SCP,
            lambda s: bedrock(s).delete_guardrail(guardrailIdentifier="probe0000000"),
        ),
        Probe(
            "breakglass",
            "bedrock:DeleteGuardrail (the AI/ML SCPs have no exemptions)",
            SCP,
            lambda s: bedrock(s).delete_guardrail(guardrailIdentifier="probe0000000"),
        ),
        Probe("workload", "bedrock:ListGuardrails", NOT_DENIED, lambda s: bedrock(s).list_guardrails()),
        # --- Bedrock model allow-list (amazon.titan*, amazon.nova-2-lite*)
        Probe(
            "workload",
            "bedrock:InvokeModel, model off the allow-list",
            SCP,
            converse("meta.llama3-8b-instruct-v1:0"),
        ),
        Probe(
            "workload",
            "bedrock:InvokeModel, allow-listed model",
            NOT_DENIED,
            embed,
        ),
        Probe(
            "workload",
            "bedrock:InvokeModel, inference profile of an allow-listed model",
            NOT_DENIED,
            converse("us.amazon.nova-2-lite-v1:0"),
        ),
        Probe(
            "workload",
            "bedrock:InvokeModel, inference profile of a model off the allow-list",
            SCP,
            converse("us.meta.llama3-3-70b-instruct-v1:0"),
        ),
        # --- SageMaker notebooks
        Probe(
            "workload",
            "sagemaker:CreateNotebookInstance with direct internet access",
            SCP,
            notebook(DirectInternetAccess="Enabled"),
        ),
        Probe("workload", "sagemaker:CreateNotebookInstance with root access", SCP, notebook(RootAccess="Enabled")),
        Probe(
            "workload",
            "sagemaker:CreateNotebookInstance without a subnet",
            SCP,
            notebook(SubnetId=None, SecurityGroupIds=None),
        ),
        Probe("workload", "sagemaker:CreateNotebookInstance without a KMS key", SCP, notebook(KmsKeyId=None)),
        Probe(
            "workload",
            "sagemaker:CreateNotebookInstance in a VPC, no internet, no root, with a KMS key (subnet does not exist)",
            NOT_DENIED,
            notebook(),
        ),
        Probe(
            "workload",
            "sagemaker:UpdateNotebookInstance to root access, on that notebook",
            SCP,
            lambda s: sagemaker(s).update_notebook_instance(NotebookInstanceName=PROBE, RootAccess="Enabled"),
        ),
        # --- SageMaker training jobs
        Probe("workload", "sagemaker:CreateTrainingJob without a volume KMS key", SCP, training_job(volume_key=False)),
        Probe("workload", "sagemaker:CreateTrainingJob without an output KMS key", SCP, training_job(output_key=False)),
        Probe("workload", "sagemaker:CreateTrainingJob with both KMS keys", NOT_DENIED, training_job()),
        # --- IAM users: Bedrock and Amazon SES (iam-user has bedrock:* and ses:* allowed)
        Probe("iam-user", "bedrock:ListFoundationModels", SCP, lambda s: bedrock(s).list_foundation_models()),
        Probe("iam-user", "bedrock:InvokeModel, allow-listed model", SCP, embed),
        Probe(
            "iam-user",
            "bedrock:ListGuardrails (not a model action)",
            NOT_DENIED,
            lambda s: bedrock(s).list_guardrails(),
        ),
        Probe("workload", "bedrock:ListFoundationModels", NOT_DENIED, lambda s: bedrock(s).list_foundation_models()),
        Probe("iam-user", "ses:GetAccount", SCP, lambda s: s.client("sesv2").get_account()),
        Probe("workload", "ses:GetAccount", NOT_DENIED, lambda s: s.client("sesv2").get_account()),
        # --- AWS RAM: shares stay inside the organization
        Probe("workload", "ram:CreateResourceShare allowing external principals", SCP, share("denied", True)),
        Probe("workload", "ram:CreateResourceShare, organization only", NOT_DENIED, share("internal", False)),
        Probe(
            "breakglass", "ram:CreateResourceShare allowing external principals", NOT_DENIED, share("external", True)
        ),
        Probe(
            "workload",
            "ram:AssociateResourceShare to the share that allows external principals",
            SCP,
            # A subnet that does not exist: an allowed call fails validation.
            lambda s: ram(s).associate_resource_share(
                resourceShareArn=shares.get("external", f"arn:{partition}:ram:us-east-1:{account_id}:resource-share/x"),
                resourceArns=[f"arn:{partition}:ec2:us-east-1:{account_id}:subnet/subnet-{MISSING}"],
            ),
        ),
    ]


def create_user(breakglass: boto3.Session) -> boto3.Session:
    """Create the probe IAM user as the exempt role and return a session signed with its key."""
    iam = breakglass.client("iam")
    iam.create_user(UserName=USER)
    iam.put_user_policy(
        UserName=USER,
        PolicyName="probe",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["bedrock:*", "ses:*"], "Resource": "*"}],
            }
        ),
    )
    key = iam.create_access_key(UserName=USER)["AccessKey"]
    session = boto3.Session(
        aws_access_key_id=key["AccessKeyId"], aws_secret_access_key=key["SecretAccessKey"], region_name="us-east-1"
    )
    # A new key is not valid everywhere at once. Without the wait, a probe
    # would be rejected for its signature and look like a guardrail.
    for _ in range(30):
        with contextlib.suppress(ClientError):
            session.client("sts").get_caller_identity()
            break
        time.sleep(2)
    time.sleep(20)
    return session


def delete_user(breakglass: boto3.Session) -> None:
    iam = breakglass.client("iam")
    with contextlib.suppress(ClientError):
        for key in iam.list_access_keys(UserName=USER)["AccessKeyMetadata"]:
            iam.delete_access_key(UserName=USER, AccessKeyId=key["AccessKeyId"])
        iam.delete_user_policy(UserName=USER, PolicyName="probe")
        iam.delete_user(UserName=USER)


def create_sagemaker_fixtures(base: boto3.Session) -> tuple[str, str]:
    """Create the execution role and KMS key that SageMaker resolves before it checks authorization."""
    key_arn = base.client("kms").create_key(Description=f"{PROBE}: live proof only")["KeyMetadata"]["Arn"]
    base.client("kms").enable_key_rotation(KeyId=key_arn)
    iam = base.client("iam")
    role_arn = iam.create_role(
        RoleName=ROLE,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
    )["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=ROLE,
        PolicyName="probe",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "kms:DescribeKey", "Resource": key_arn}],
            }
        ),
    )
    time.sleep(15)  # a new role cannot be assumed straight away
    return role_arn, key_arn


def delete_leftovers(base: boto3.Session, breakglass: boto3.Session, shares: dict[str, str], key_arn: str) -> None:
    for arn in shares.values():
        with contextlib.suppress(ClientError):
            breakglass.client("ram").delete_resource_share(resourceShareArn=arn)
    sagemaker = base.client("sagemaker")
    # Only reachable if the instance quota is above zero.
    with contextlib.suppress(ClientError):
        sagemaker.stop_training_job(TrainingJobName=PROBE)
    # The notebook has no valid subnet. It can be deleted once it has failed.
    with contextlib.suppress(ClientError):
        for _ in range(60):
            if sagemaker.describe_notebook_instance(NotebookInstanceName=PROBE)["NotebookInstanceStatus"] != "Pending":
                break
            time.sleep(10)
        sagemaker.delete_notebook_instance(NotebookInstanceName=PROBE)
    with contextlib.suppress(ClientError):
        base.client("iam").delete_role_policy(RoleName=ROLE, PolicyName="probe")
        base.client("iam").delete_role(RoleName=ROLE)
    with contextlib.suppress(ClientError):
        base.client("kms").schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)


def sso_token(start_region: str) -> str:
    """Newest unexpired IAM Identity Center access token in the AWS CLI cache."""
    tokens = []
    for path in (Path.home() / ".aws" / "sso" / "cache").glob("*.json"):
        data = json.loads(path.read_text())
        if "accessToken" in data and data.get("region") == start_region:
            tokens.append((data["expiresAt"], data["accessToken"]))
    if not tokens:
        sys.exit("No cached IAM Identity Center token. Run `aws sso login` first.")
    return max(tokens)[1]


def identity_center_checks(management: boto3.Session, sandbox: boto3.Session, out: dict) -> list[tuple[str, str, str]]:
    """Read the permission set back from Identity Center and from IAM in the sandbox account."""
    admin = management.client("sso-admin", region_name=out["identity_center_region"])
    ids = {"InstanceArn": out["instance_arn"], "PermissionSetArn": out["permission_set_arn"]}
    name = out["permission_set_name"]
    boundary_name = out["boundary_policy_arn"].rsplit("/", 1)[1]

    managed = [p["Name"] for p in admin.list_managed_policies_in_permission_set(**ids)["AttachedManagedPolicies"]]
    inline = json.loads(admin.get_inline_policy_for_permission_set(**ids)["InlinePolicy"])
    boundary = admin.get_permissions_boundary_for_permission_set(**ids)["PermissionsBoundary"]
    assignments = admin.list_account_assignments(AccountId=out["sandbox_account_id"], **ids)["AccountAssignments"]

    iam = sandbox.client("iam")
    roles = iam.list_roles(PathPrefix="/aws-reserved/sso.amazonaws.com/")["Roles"]
    role = next(r["RoleName"] for r in roles if r["RoleName"].startswith(f"AWSReservedSSO_{name}_"))
    role_boundary = iam.get_role(RoleName=role)["Role"].get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")

    return [
        (
            "Session duration",
            "PT1H",
            admin.describe_permission_set(**ids)["PermissionSet"]["SessionDuration"],
        ),
        ("AWS managed policies", "AdministratorAccess", ", ".join(managed)),
        ("Inline policy statement", "ProofInlineDeny", ", ".join(s["Sid"] for s in inline["Statement"])),
        (
            "Permissions boundary on the permission set",
            boundary_name,
            boundary.get("CustomerManagedPolicyReference", {}).get("Name", "none"),
        ),
        ("Account assignments", "1 USER", f"{len(assignments)} {assignments[0]['PrincipalType']}"),
        ("Permissions boundary on the role provisioned in the account", out["boundary_policy_arn"], str(role_boundary)),
    ]


def sso_session(out: dict) -> boto3.Session:
    """Sign in to the sandbox account with the proof permission set."""
    region = out["identity_center_region"]
    creds = boto3.client("sso", region_name=region).get_role_credentials(
        roleName=out["permission_set_name"], accountId=out["sandbox_account_id"], accessToken=sso_token(region)
    )["roleCredentials"]
    return boto3.Session(
        aws_access_key_id=creds["accessKeyId"],
        aws_secret_access_key=creds["secretAccessKey"],
        aws_session_token=creds["sessionToken"],
        region_name="us-east-1",
    )


def sso_probes(account_id: str) -> list[Probe]:
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": account_id}, "Action": "sts:AssumeRole"}],
        }
    )
    return [
        Probe("sso", "s3:ListAllMyBuckets", NOT_DENIED, lambda s: s.client("s3").list_buckets()),
        Probe(
            "sso",
            "iam:CreateRole without the boundary",
            BOUNDARY,
            lambda s: s.client("iam").create_role(
                RoleName=f"{PROBE}-nob", Path="/workload/", AssumeRolePolicyDocument=trust
            ),
        ),
        Probe(
            "sso",
            "organizations:DescribeOrganization",
            UNNAMED_DENY,
            lambda s: s.client("organizations").describe_organization(),
        ),
        Probe("sso", "iam:GetAccountSummary", IDENTITY, lambda s: s.client("iam").get_account_summary()),
    ]


def masked(line: str) -> str:
    return re.sub(r"\b\d{12}\b", "111122223333", line)


def run(probes: list[Probe], sessions: dict[str, boto3.Session]) -> int:
    print("| Principal | Request | Expected | Result | Detail | |")
    print("|---|---|---|---|---|---|")
    failures = 0
    for probe in probes:
        actual, detail = classify(sessions[probe.principal], probe.call)
        ok = actual == probe.expected
        failures += not ok
        row = (probe.principal, probe.description, probe.expected, actual, detail, "pass" if ok else "**FAIL**")
        print(masked("| " + " | ".join(row) + " |"))
    print(f"\n{len(probes) - failures}/{len(probes)} probes matched their expectation.\n")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--profile", required=True, help="administrator in the sandbox account")
    parser.add_argument("--management-profile", required=True)
    parser.add_argument("--outputs", required=True, help="file written by `terraform output -json`")
    args = parser.parse_args()

    out = {k: v["value"] for k, v in json.loads(Path(args.outputs).read_text()).items()}
    account_id = out["sandbox_account_id"]
    base = boto3.Session(profile_name=args.profile, region_name="us-east-1")
    partition = base.client("sts").get_caller_identity()["Arn"].split(":")[1]
    breakglass = assume(base, out["breakglass_role_arn"])
    shares: dict[str, str] = {}
    key_arn = ""

    print("## Service control policies\n")
    try:
        role_arn, key_arn = create_sagemaker_fixtures(base)
        sessions = {"workload": base, "breakglass": breakglass, "iam-user": create_user(breakglass)}
        failures = run(build_probes(partition, account_id, role_arn, key_arn, shares), sessions)
    finally:
        delete_user(breakglass)
        delete_leftovers(base, breakglass, shares, key_arn)

    print("## Identity Center permission set\n")
    print("| Read back | Expected | Result | |")
    print("|---|---|---|---|")
    management = boto3.Session(profile_name=args.management_profile)
    for description, expected, actual in identity_center_checks(management, base, out):
        ok = expected == actual
        failures += not ok
        print(masked(f"| {description} | {expected} | {actual} | {'pass' if ok else '**FAIL**'} |"))
    print()

    try:
        failures += run(sso_probes(account_id), {"sso": sso_session(out)})
    finally:
        with contextlib.suppress(ClientError):
            breakglass.client("iam").delete_role(RoleName=f"{PROBE}-nob")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
