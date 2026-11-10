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
def ssc_locked() -> RenderedPolicies:
    # Every optional core statement on, so the size test sees the largest bundle.
    return render(
        extra_vars={
            "deny_service_specific_credentials": True,
            "deny_ses_to_iam_users": True,
            "ses_iam_user_exempt_principal_arns": ["arn:aws:iam::*:user/ses-smtp-*"],
            "third_party_vendor_networks": VENDOR_NETWORKS,
        }
    )


# Two vendors with realistic list lengths. Addresses are documentation ranges.
VENDOR_NETWORKS = {
    "Fireworks": {
        "principal_arns": ["arn:aws:iam::*:role/vendor-fireworks-*", "arn:aws:iam::*:user/vendor-fireworks-*"],
        "source_cidrs": ["203.0.113.0/24", "198.51.100.16/28", "2001:db8::/32"],
    },
    "Notetaker": {
        "principal_arns": ["arn:aws:iam::*:role/vendor-notetaker-*"],
        "source_cidrs": ["192.0.2.0/24", "192.0.2.128/25"],
    },
}


@pytest.fixture(scope="session")
def vendor_locked() -> RenderedPolicies:
    return render(extra_vars={"third_party_vendor_networks": VENDOR_NETWORKS})


@pytest.fixture(scope="session")
def hop_locked() -> RenderedPolicies:
    return render(extra_vars={"require_imds_hop_limit_one": True})


@pytest.fixture(scope="session")
def data_locked() -> RenderedPolicies:
    # Every optional data-and-compute statement on, so the size test sees the largest bundle.
    return render(
        extra_vars={
            "require_imds_hop_limit_one": True,
            "deny_athena_results_bucket_outside_org": True,
            "deny_tagged_kms_keys_off_org_network": True,
        }
    )


@pytest.fixture(scope="session")
def govcloud() -> RenderedPolicies:
    return render(partition="aws-us-gov")
