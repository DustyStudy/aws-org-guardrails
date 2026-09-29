"""Render the policies module with Terraform and return the policy documents.

The fixture in tests/fixtures/render has no provider, so `terraform plan` runs
offline and needs no AWS credentials. Reading the planned outputs (instead of
re-implementing the policies in Python) means the tests exercise exactly the
JSON that Terraform would deploy.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "render"


@dataclass(frozen=True)
class RenderedPolicies:
    scps: dict[str, dict[str, Any]]
    scps_raw: dict[str, str]
    boundary: dict[str, Any]


def terraform_binary() -> str:
    binary = os.environ.get("TERRAFORM", "terraform")
    found = shutil.which(binary)
    if not found:
        raise FileNotFoundError(f"terraform binary {binary!r} not found; set TERRAFORM or add it to PATH")
    return found


def render(partition: str = "aws", allowed_regions: list[str] | None = None) -> RenderedPolicies:
    tf = terraform_binary()
    regions = allowed_regions or (
        ["us-gov-west-1", "us-gov-east-1"] if partition == "aws-us-gov" else ["us-east-1", "us-west-2"]
    )
    tf_vars = [f"-var=partition={partition}", f"-var=allowed_regions={json.dumps(regions)}"]

    with tempfile.TemporaryDirectory() as tmp:
        env = {**os.environ, "TF_DATA_DIR": str(Path(tmp) / ".terraform"), "TF_IN_AUTOMATION": "1"}
        plan = str(Path(tmp) / "plan.bin")
        run = dict(cwd=FIXTURE, env=env, check=True, capture_output=True, text=True)
        subprocess.run([tf, "init", "-input=false", "-backend=false"], **run)  # noqa: S603
        subprocess.run([tf, "plan", "-input=false", "-lock=false", f"-out={plan}", *tf_vars], **run)  # noqa: S603
        shown = subprocess.run([tf, "show", "-json", plan], **run)  # noqa: S603

    outputs = json.loads(shown.stdout)["planned_values"]["outputs"]
    raw = outputs["scp_policies"]["value"]
    return RenderedPolicies(
        scps={name: json.loads(doc) for name, doc in raw.items()},
        scps_raw=raw,
        boundary=json.loads(outputs["permissions_boundary_policy"]["value"]),
    )
