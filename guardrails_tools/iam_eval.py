"""A small, strict evaluator for the subset of IAM policy language these guardrails use.

It answers one question: given a set of policy documents and a request, is the
result an explicit deny, an allow, or an implicit deny? That is enough to test
guardrails as behavior ("can a workload role stop CloudTrail?") instead of as
strings ("does the JSON contain cloudtrail:StopLogging?").

It is deliberately not a full IAM simulator:

* Only the condition operators listed in ``_OPERATORS`` are supported. Any other
  operator raises ``UnsupportedPolicyFeature`` instead of being ignored, so a
  new statement can never pass a test just because the evaluator skipped it.
* Multi-valued context keys and ``ForAnyValue``/``ForAllValues`` are not
  supported, for the same reason.
* Resource ARNs with a policy variable in the account field raise too. IAM
  rejects them at CreatePolicy ("failed legacy parsing") even though IAM
  Access Analyzer and the policy simulator accept them.
* It models one policy layer at a time. Resource policies, session policies
  and the SCP inheritance chain are out of scope.

For a second opinion from AWS itself, see ``scripts/validate_policies.py``,
which sends the same rendered documents to IAM Access Analyzer.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

# FullAWSAccess, the AWS managed SCP that is attached to every root, OU and
# account by default. Deny-list SCPs only mean something alongside it.
FULL_AWS_ACCESS: dict[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}


class UnsupportedPolicyFeature(ValueError):
    """The policy uses something this evaluator does not model."""


class Decision(StrEnum):
    EXPLICIT_DENY = "explicit_deny"
    ALLOW = "allow"
    IMPLICIT_DENY = "implicit_deny"


@dataclass(frozen=True)
class Request:
    """One API call as IAM sees it. Context keys are matched case-insensitively."""

    action: str
    resource: str = "*"
    context: Mapping[str, str] = field(default_factory=dict)

    def context_value(self, key: str) -> str | None:
        wanted = key.lower()
        for k, v in self.context.items():
            if k.lower() == wanted:
                if not isinstance(v, str):
                    raise UnsupportedPolicyFeature(f"context key {key!r} must be a single string value")
                return v
        return None


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    # IAM wildcards: * matches any run of characters (including none, and
    # including ':' and '/'), ? matches exactly one. Nothing else is special.
    parts = []
    for ch in pattern:
        if ch == "*":
            parts.append(".*")
        elif ch == "?":
            parts.append(".")
        else:
            parts.append(re.escape(ch))
    return re.compile("".join(parts), re.DOTALL)


def glob_match(pattern: str, value: str, *, case_sensitive: bool = True) -> bool:
    if not case_sensitive:
        pattern, value = pattern.lower(), value.lower()
    return _glob_to_regex(pattern).fullmatch(value) is not None


_VARIABLE = re.compile(r"\$\{([^}]*)\}")
_ESCAPES = {"*": "*", "?": "?", "$": "$"}


def substitute_variables(text: str, request: Request) -> str | None:
    """Replace ${key} policy variables. Returns None if a key is missing,
    because IAM treats an element with an unresolvable variable as no match."""
    missing = False

    def repl(m: re.Match[str]) -> str:
        nonlocal missing
        name = m.group(1)
        if name in _ESCAPES:
            return _ESCAPES[name]
        value = request.context_value(name)
        if value is None:
            missing = True
            return ""
        return value

    result = _VARIABLE.sub(repl, text)
    return None if missing else result


def _string_equals(pattern: str, value: str) -> bool:
    return pattern == value


def _string_equals_ignore_case(pattern: str, value: str) -> bool:
    return pattern.lower() == value.lower()


def _string_like(pattern: str, value: str) -> bool:
    return glob_match(pattern, value)


def _bool(pattern: str, value: str) -> bool:
    return pattern.lower() == value.lower()


# name -> (matcher, negated)
_OPERATORS: dict[str, tuple[Any, bool]] = {
    "StringEquals": (_string_equals, False),
    "StringNotEquals": (_string_equals, True),
    "StringEqualsIgnoreCase": (_string_equals_ignore_case, False),
    "StringNotEqualsIgnoreCase": (_string_equals_ignore_case, True),
    "StringLike": (_string_like, False),
    "StringNotLike": (_string_like, True),
    # IAM's ArnEquals and ArnLike both accept wildcards.
    "ArnEquals": (_string_like, False),
    "ArnLike": (_string_like, False),
    "ArnNotEquals": (_string_like, True),
    "ArnNotLike": (_string_like, True),
    "Bool": (_bool, False),
}


def _condition_holds(operator: str, key: str, values: Any, request: Request) -> bool:
    if operator.startswith(("ForAnyValue:", "ForAllValues:")):
        raise UnsupportedPolicyFeature(f"set operator {operator!r} is not supported")

    if_exists = operator.endswith("IfExists")
    base = operator[: -len("IfExists")] if if_exists else operator
    actual = request.context_value(key)

    if base == "Null":
        want_absent = str(_as_list(values)[0]).lower() == "true"
        return (actual is None) == want_absent

    if base not in _OPERATORS:
        raise UnsupportedPolicyFeature(f"condition operator {operator!r} is not supported")
    matcher, negated = _OPERATORS[base]

    if actual is None:
        # A missing key makes positive operators false and negated operators
        # true, unless ...IfExists, which makes either operator true.
        return if_exists or negated

    matched = False
    for raw in _as_list(values):
        pattern = substitute_variables(str(raw), request)
        if pattern is not None and matcher(pattern, actual):
            matched = True
            break
    return not matched if negated else matched


def _conditions_hold(conditions: Mapping[str, Mapping[str, Any]], request: Request) -> bool:
    return all(
        _condition_holds(operator, key, values, request)
        for operator, keyed in conditions.items()
        for key, values in keyed.items()
    )


def _any_pattern_matches(patterns: Iterable[str], value: str, request: Request, *, case_sensitive: bool) -> bool:
    for raw in patterns:
        pattern = substitute_variables(raw, request)
        if pattern is not None and glob_match(pattern, value, case_sensitive=case_sensitive):
            return True
    return False


def _check_resource_arns(patterns: Iterable[str]) -> None:
    for pattern in patterns:
        parts = pattern.split(":", 5)
        if len(parts) == 6 and "${" in parts[4]:
            raise UnsupportedPolicyFeature(
                f"{pattern!r}: IAM rejects a policy variable in the account field of a resource ARN"
            )


def statement_applies(statement: Mapping[str, Any], request: Request) -> bool:
    known = {"Sid", "Effect", "Action", "NotAction", "Resource", "NotResource", "Condition"}
    unknown = set(statement) - known
    if unknown:
        raise UnsupportedPolicyFeature(f"statement elements {sorted(unknown)} are not supported")

    if "Action" in statement:
        if not _any_pattern_matches(_as_list(statement["Action"]), request.action, request, case_sensitive=False):
            return False
    elif "NotAction" in statement:
        if _any_pattern_matches(_as_list(statement["NotAction"]), request.action, request, case_sensitive=False):
            return False
    else:
        raise UnsupportedPolicyFeature("statement has neither Action nor NotAction")

    _check_resource_arns(_as_list(statement.get("Resource", statement.get("NotResource", []))))

    if "Resource" in statement:
        if not _any_pattern_matches(_as_list(statement["Resource"]), request.resource, request, case_sensitive=True):
            return False
    elif "NotResource" in statement:
        if _any_pattern_matches(_as_list(statement["NotResource"]), request.resource, request, case_sensitive=True):
            return False
    else:
        raise UnsupportedPolicyFeature("statement has neither Resource nor NotResource")

    return _conditions_hold(statement.get("Condition", {}), request)


def evaluate(policies: Iterable[Mapping[str, Any]], request: Request) -> Decision:
    """Evaluate policy documents as one layer: explicit deny wins, then allow."""
    allowed = False
    for policy in policies:
        for statement in _as_list(policy["Statement"]):
            if not statement_applies(statement, request):
                continue
            if statement["Effect"] == "Deny":
                return Decision.EXPLICIT_DENY
            if statement["Effect"] == "Allow":
                allowed = True
            else:
                raise UnsupportedPolicyFeature(f"unknown Effect {statement['Effect']!r}")
    return Decision.ALLOW if allowed else Decision.IMPLICIT_DENY


def scp_decision(scps: Iterable[Mapping[str, Any]], request: Request) -> Decision:
    """Evaluate deny-list SCPs the way they are deployed: next to FullAWSAccess."""
    return evaluate([*scps, FULL_AWS_ACCESS], request)
