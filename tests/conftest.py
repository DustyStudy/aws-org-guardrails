import pytest

from guardrails_tools.render import RenderedPolicies, render


@pytest.fixture(scope="session")
def commercial() -> RenderedPolicies:
    return render(partition="aws")


@pytest.fixture(scope="session")
def govcloud() -> RenderedPolicies:
    return render(partition="aws-us-gov")
