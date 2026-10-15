import json
from pathlib import Path

import pytest
from incident_investigator.collectors.doctor import inspect_config
from incident_investigator.security.cli import app
from incident_investigator.security.identity import IdentityRequirement
from typer.testing import CliRunner

REQUIREMENT = IdentityRequirement(
    profile="operator",
    account_id="000000000000",
    region="eu-central-1",
    collector_role_name="IncidentCollector",
)
CONFIG = b"""[profile operator]
sso_session = company
sso_account_id = 000000000000
sso_role_name = Bootstrap
region = eu-central-1
[sso-session company]
sso_start_url = https://example.awsapps.com/start
sso_region = eu-central-1
sso_registration_scopes = sso:account:access
"""


def test_valid_config_is_not_proof_of_identity_mfa_or_live_readiness() -> None:
    result = inspect_config(CONFIG, REQUIREMENT, {})
    assert result.configuration_valid and not result.live_enabled
    assert "independent_mfa_configuration_verification" in result.remaining_gates
    assert "dedicated_role_assumption_and_identity_verification" in result.remaining_gates


@pytest.mark.parametrize(
    "key",
    [
        "AWS_ACCESS_KEY_ID",
        "AWS_ENDPOINT_URL",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_CA_BUNDLE",
    ],
)
def test_ambient_sources_and_endpoint_overrides_are_denied(key: str) -> None:
    result = inspect_config(CONFIG, REQUIREMENT, {key: "private-value"})
    assert not result.configuration_valid
    assert "private-value" not in result.model_dump_json()


@pytest.mark.parametrize(
    "raw",
    [
        CONFIG.replace(b"eu-central-1", b"us-east-1"),
        CONFIG.replace(b"000000000000", b"111111111111"),
        CONFIG.replace(b"sso_role_name = Bootstrap", b"credential_process = secret-command"),
        CONFIG.replace(b"https://example.awsapps.com/start", b"https://attacker.example/start"),
        CONFIG + b"endpoint_url = https://attacker.example",
        CONFIG.replace(b"sso_session = company", b"sso_session = absent"),
        CONFIG.replace(b"sso:account:access", b"anything"),
        b"[DEFAULT]\nregion=eu-central-1\n" + CONFIG,
        CONFIG + b"\nsso_region = duplicate-secret",
        b"\xff",
        pytest.param(b"x" * 65537, id="oversized"),
    ],
)
def test_invalid_configuration_never_leaks_input(raw: bytes) -> None:
    result = inspect_config(raw, REQUIREMENT, {})
    assert not result.configuration_valid and not result.live_enabled
    assert "secret" not in result.model_dump_json()
    assert "attacker.example" not in result.model_dump_json()


def test_doctor_cli_is_offline_and_returns_only_check_codes(tmp_path: Path) -> None:
    config = tmp_path / "config"
    config.write_bytes(CONFIG)
    options = [
        "doctor",
        "--config",
        str(config),
        "--profile",
        "operator",
        "--account",
        "000000000000",
        "--region",
        "eu-central-1",
        "--role",
        "IncidentCollector",
    ]
    result = CliRunner().invoke(app, options, env={"AWS_EC2_METADATA_DISABLED": "true"})
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["configuration_valid"]
    assert not json.loads(result.stdout)["live_enabled"]
    assert str(config) not in result.stdout
    config.write_bytes(b"invalid-secret")
    result = CliRunner().invoke(app, options)
    assert result.exit_code == 2 and "invalid-secret" not in result.stdout
