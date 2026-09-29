"""Validate the rendered policies with IAM Access Analyzer.

The pytest suite checks behavior with a local evaluator. This script asks AWS
itself: it sends each rendered SCP (as SERVICE_CONTROL_POLICY) and the
permissions boundary (as IDENTITY_POLICY) to Access Analyzer's ValidatePolicy
API, which checks grammar, unknown actions and condition keys, and security
warnings. ValidatePolicy is read-only and does not need an analyzer.

Usage (needs AWS credentials with access-analyzer:ValidatePolicy):

    pip install -r requirements-validate.txt
    python scripts/validate_policies.py                      # commercial
    python scripts/validate_policies.py --partition aws-us-gov --region us-gov-west-1

Exits 1 if any policy has an ERROR or SECURITY_WARNING finding.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import boto3

from guardrails_tools.render import render

BLOCKING = {"ERROR", "SECURITY_WARNING"}


def validate(client, name: str, document: dict, policy_type: str) -> int:
    findings = []
    paginator = client.get_paginator("validate_policy")
    for page in paginator.paginate(policyDocument=json.dumps(document), policyType=policy_type):
        findings.extend(page["findings"])

    blocking = [f for f in findings if f["findingType"] in BLOCKING]
    status = "FAIL" if blocking else "ok"
    print(f"[{status}] {name} ({policy_type}): {len(findings)} finding(s)")
    for f in findings:
        print(f"    {f['findingType']}: {f['issueCode']}: {f['findingDetails']}")
    return len(blocking)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--partition", default="aws", choices=["aws", "aws-us-gov", "aws-cn"])
    parser.add_argument("--region", default=None, help="region for the Access Analyzer endpoint")
    args = parser.parse_args()

    rendered = render(partition=args.partition)
    client = boto3.client("accessanalyzer", region_name=args.region)

    failures = 0
    for name, doc in rendered.scps.items():
        failures += validate(client, f"scp/{name}", doc, "SERVICE_CONTROL_POLICY")
    failures += validate(client, "permissions-boundary", rendered.boundary, "IDENTITY_POLICY")

    print(f"\n{failures} blocking finding(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
