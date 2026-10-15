"""Pure bootstrap checks. This module neither obtains credentials nor enables live mode."""

import re
from collections.abc import Mapping
from typing import Literal

from incident_investigator.evaluation.models import Contract, Identifier
from incident_investigator.security.policy import Account


class IdentityRequirement(Contract):
    profile: Identifier
    account_id: Account
    region: Identifier
    collector_role_name: Identifier
    mfa_configuration: Literal["unverified", "phishing_resistant_verified"] = "unverified"


def validate_profile(
    requirement: IdentityRequirement,
    profile: Mapping[str, str],
    environment: Mapping[str, str],
) -> None:
    # Reject inherited long-lived credentials and alternate endpoint injection.
    if any(
        key
        in (
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_SECURITY_TOKEN",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "AWS_ROLE_ARN",
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "AWS_CONTAINER_AUTHORIZATION_TOKEN",
            "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
            "AWS_CA_BUNDLE",
        )
        or key.startswith("AWS_ENDPOINT_URL")
        for key in environment
    ):
        raise ValueError("ambient_credentials_or_endpoint_override")
    if set(profile) - {"sso_session", "sso_role_name", "sso_account_id", "region", "output"}:
        raise ValueError("unsupported_profile")
    if not profile.get("sso_session") or not profile.get("sso_role_name"):
        raise ValueError("identity_center_required")
    if profile.get("sso_account_id") != requirement.account_id:
        raise ValueError("account_mismatch")
    if profile.get("region") != requirement.region:
        raise ValueError("region_mismatch")
    if any(
        environment.get(key, requirement.region) != requirement.region
        for key in ("AWS_REGION", "AWS_DEFAULT_REGION")
    ):
        raise ValueError("region_override")
    if not re.fullmatch(r"[A-Za-z0-9+=,.@_-]{1,64}", requirement.collector_role_name):
        raise ValueError("invalid_collector_role")


def validate_bootstrap(
    requirement: IdentityRequirement,
    profile: Mapping[str, str],
    caller_account: str,
    environment: Mapping[str, str],
) -> None:
    validate_profile(requirement, profile, environment)
    if caller_account != requirement.account_id:
        raise ValueError("account_mismatch")
    # This must eventually come from a trusted configuration verifier, not STS.
    if requirement.mfa_configuration != "phishing_resistant_verified":
        raise ValueError("mfa_configuration_unverified")


def validate_assumed_identity(requirement: IdentityRequirement, account: str, arn: str) -> None:
    prefix = (
        f"arn:aws:sts::{requirement.account_id}:assumed-role/{requirement.collector_role_name}/"
    )
    if account != requirement.account_id or not arn.startswith(prefix) or not arn[len(prefix) :]:
        raise ValueError("assumed_role_mismatch")
