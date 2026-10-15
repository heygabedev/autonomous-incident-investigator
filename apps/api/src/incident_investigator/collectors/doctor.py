"""Inspect an explicitly selected config without resolving credentials or contacting AWS."""

import configparser
import re
from collections.abc import Mapping
from typing import Literal

from incident_investigator.evaluation.models import Contract
from incident_investigator.security.identity import IdentityRequirement, validate_profile


class DoctorResult(Contract):
    schema_version: Literal["1.0.0"] = "1.0.0"
    configuration_valid: bool
    live_enabled: Literal[False] = False
    checks: tuple[str, ...]
    remaining_gates: tuple[str, ...] = (
        "independent_mfa_configuration_verification",
        "dedicated_role_assumption_and_identity_verification",
        "iam_and_live_adapter_acceptance",
        "transactional_budgets_and_dispatch_fencing",
    )


def inspect_config(
    raw: bytes, requirement: IdentityRequirement, environment: Mapping[str, str]
) -> DoctorResult:
    # Neither exception messages nor submitted configuration appear in the result.
    try:
        if len(raw) > 65_536:
            raise ValueError("config_too_large")
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.read_string(raw.decode("utf-8", errors="strict"))
        if parser.defaults():
            raise ValueError("inherited_config_not_supported")
        section = f"profile {requirement.profile}"
        if section not in parser:
            raise ValueError("profile_not_found")
        profile = dict(parser[section])
        validate_profile(requirement, profile, environment)
        session = f"sso-session {profile['sso_session']}"
        if session not in parser:
            raise ValueError("sso_session_not_found")
        settings = dict(parser[session])
        if set(settings) - {"sso_start_url", "sso_region", "sso_registration_scopes"}:
            raise ValueError("unsupported_sso_configuration")
        if not re.fullmatch(
            r"https://[a-zA-Z0-9-]+\.awsapps\.com/start/?", settings.get("sso_start_url", "")
        ):
            raise ValueError("unsupported_sso_start_url")
        if not re.fullmatch(r"[a-z]{2}-[a-z]+-\d", settings.get("sso_region", "")):
            raise ValueError("invalid_sso_region")
        if settings.get("sso_registration_scopes", "sso:account:access") != "sso:account:access":
            raise ValueError("unsupported_sso_scopes")
    except (configparser.Error, UnicodeError):
        return DoctorResult(configuration_valid=False, checks=("invalid_config",))
    except ValueError as error:
        # Only locally authored reason codes leave this pure validation boundary.
        return DoctorResult(configuration_valid=False, checks=(str(error),))
    return DoctorResult(
        configuration_valid=True,
        checks=(
            "explicit_identity_center_profile",
            "expected_account_and_region",
            "no_credential_or_endpoint_override",
        ),
    )
