import pytest

from guardrails_tools.render import RenderedPolicies, render


@pytest.fixture(scope="session")
def commercial() -> RenderedPolicies:
    return render(partition="aws")


@pytest.fixture(scope="session")
def ses_locked() -> RenderedPolicies:
    return render(
        extra_vars={
            "deny_ses_to_iam_users": True,
            "ses_iam_user_exempt_principal_arns": ["arn:aws:iam::*:user/ses-smtp-*"],
        }
    )


@pytest.fixture(scope="session")
def govcloud() -> RenderedPolicies:
    return render(partition="aws-us-gov")
