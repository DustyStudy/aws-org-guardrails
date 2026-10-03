# What is verified, and what is not

None of the AI/ML modules has been deployed to a live AWS account
since they were refocused on AI and ML. The evidence is offline: plan-time
tests, Lambda unit tests, static analysis, and IAM Access Analyzer policy
validation. This page lists what each covers, the numbers from the last run,
and the gaps.

Numbers are from a local run on 2026-09-29 (Terraform 1.16.4, Checkov
3.3.20). CI runs everything except Access Analyzer on every pull request.

## Summary

| Check | Result |
|---|---|
| `terraform test` (`ai-ml-guardrails`) | 11 runs, 11 passed (2026-09-30) |
| pytest (the three Lambdas) | 24 passed |
| `terraform validate` | 7 of 7 roots valid |
| Checkov (`--framework terraform`, 118 resources) | 331 passed, 0 failed, 23 skipped |
| IAM Access Analyzer `ValidatePolicy` (`SERVICE_CONTROL_POLICY`, commercial partition) | 0 findings on each of the 4 original SCPs; `deny-bedrock-long-term-credentials` (added 2026-09-30) not yet validated |
| Trivy config scan, Gitleaks, `terraform fmt`, TFLint | Run in CI on every PR |

Every Checkov skip is an inline `checkov:skip=<ID>: <reason>` comment next to
the resource.

## What the `terraform test` runs assert

The AWS provider is mocked. Each run decodes the SCP JSON that Terraform
renders and checks the statements.

| Run | What it asserts |
|---|---|
| `defaults_create_three_policies` | The defaults create the logging, notebook and encryption SCPs, leave the model allow-list off, and name each policy with `name_prefix` |
| `every_policy_attaches_to_every_target` | Every enabled policy attaches to every target, and to nothing else |
| `logging_and_guardrail_deletion_are_denied` | Deleting Bedrock invocation logging and Bedrock Guardrails is denied |
| `notebooks_need_vpc_no_internet_no_root` | Notebooks with direct internet access, root access, or no VPC subnets are denied |
| `sagemaker_requires_kms_keys` | Notebooks and training jobs without a volume or output KMS key are denied |
| `model_allow_list_keeps_inference_profiles` | With the allow-list on, only the allowed models and inference profiles are exempt from the deny |
| `bedrock_denied_to_iam_users_only` | The Bedrock deny keys only on `aws:PrincipalType = User` and covers invocation, Bedrock API keys, model discovery and model enablement |
| `bedrock_iam_user_exemptions_render` | Exempt IAM users are carved out with `ArnNotLike` on `aws:PrincipalArn` |
| `bedrock_exemption_must_be_an_iam_user` | An exemption that isn't an IAM user ARN is rejected at plan time |
| `disabled_policies_are_not_created` | Turning every policy off creates no policies and no attachments |
| `standalone_json_matches_module` | Each file in `policies/ai-ml-guardrails/` matches the policy the module renders, so the standalone JSON cannot drift |

## What the pytest suites cover

The boto3 clients are replaced with mocks. The suites check what each
Lambda must and must not touch:

- `bedrock-logging-enforcement` (8 tests): a compliant configuration is
  left alone; a missing one is re-enabled and notified; logging to another
  bucket counts as drift; with no destination configured, the function
  refuses to act.
- `ai-agent-iam-auditor` (8 tests): an AI-service role with admin rights is
  flagged, a scoped one is not; a role found through both a trust policy
  and a Bedrock Agent action group is reported once.
- `sagemaker-notebook-exposure` (8 tests): an exposed running notebook is
  tagged and stopped; a notebook whose update fails keeps its
  pending-remediation tag.

## Reproduce it

```bash
# Plan-time SCP tests (no AWS credentials needed)
terraform -chdir=modules/ai-ml-guardrails init -backend=false
terraform -chdir=modules/ai-ml-guardrails test

# Lambda tests
pip install pytest boto3
python -m pytest tests -q

# Static analysis
checkov -d terraform --framework terraform

# Access Analyzer (needs credentials with access-analyzer:ValidatePolicy)
for f in policies/ai-ml-guardrails/*.json; do
  aws accessanalyzer validate-policy \
    --policy-type SERVICE_CONTROL_POLICY \
    --policy-document "file://$f" \
    --query 'findings[].[findingType,issueCode]' --output text
done
```

## Gaps

- **No live deployment.** The tests show what Terraform will request and
  that the policy grammar is valid. They do not show how AWS evaluates the
  SCPs against real Bedrock and SageMaker calls. For SCPs probed with real
  API calls, see the live proof in
  [aws-org-guardrails](https://github.com/DustyStudy/aws-org-guardrails/blob/main/docs/PROOF.md).
- **Only `ai-ml-guardrails` has a `terraform test` suite.** The other five
  modules are covered by `terraform validate`, Checkov, Trivy and TFLint,
  plus pytest for their Lambdas.
- **Access Analyzer ran in the commercial partition only.** GovCloud was not
  checked.
- **`claude-apps-gateway` is a reference deployment** of a third-party
  container. Nothing here tests the gateway itself.
