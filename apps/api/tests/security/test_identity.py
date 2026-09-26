import pytest
from incident_investigator.security.identity import (
    IdentityRequirement,
    validate_assumed_identity,
    validate_bootstrap,
)

REQUIREMENT = IdentityRequirement(
    profile="sso",
    account_id="000000000000",
    region="eu-central-1",
    collector_role_name="Collector",
    mfa_configuration="phishing_resistant_verified",
)
PROFILE = {
    "sso_session": "company",
    "sso_role_name": "Bootstrap",
    "sso_account_id": "000000000000",
    "region": "eu-central-1",
}


def test_bootstrap_requires_separate_mfa_evidence() -> None:
    validate_bootstrap(REQUIREMENT, PROFILE, "000000000000", {})
    with pytest.raises(ValueError, match="mfa_configuration_unverified"):
        validate_bootstrap(
            REQUIREMENT.model_copy(update={"mfa_configuration": "unverified"}),
            PROFILE,
            "000000000000",
            {},
        )


@pytest.mark.parametrize(
    "key",
    ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ENDPOINT_URL_STS"],
)
def test_ambient_credentials_or_endpoint_rejected(key: str) -> None:
    with pytest.raises(ValueError):
        validate_bootstrap(REQUIREMENT, PROFILE, "000000000000", {key: "not-used"})


@pytest.mark.parametrize(
    "change",
    [
        {"credential_process": "arbitrary"},
        {"source_profile": "admin"},
        {"sso_session": ""},
        {"sso_account_id": "111111111111"},
        {"region": "us-east-1"},
    ],
)
def test_bad_profiles_are_rejected(change: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        validate_bootstrap(REQUIREMENT, PROFILE | change, "000000000000", {})


def test_assumed_role_has_no_fallback() -> None:
    validate_assumed_identity(
        REQUIREMENT, "000000000000", "arn:aws:sts::000000000000:assumed-role/Collector/session"
    )
    for arn in (
        "arn:aws:iam::000000000000:user/admin",
        "arn:aws:sts::000000000000:assumed-role/Admin/session",
    ):
        with pytest.raises(ValueError):
            validate_assumed_identity(REQUIREMENT, "000000000000", arn)
