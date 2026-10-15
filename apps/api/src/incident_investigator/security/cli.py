import os
import sqlite3
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Literal

import typer

from incident_investigator.collectors.doctor import DoctorResult, inspect_config
from incident_investigator.evaluation.canonical import MAX_BYTES
from incident_investigator.infrastructure.plans import PlanCheck, check_plan
from incident_investigator.security.authority import SecurityAuthority
from incident_investigator.security.identity import IdentityRequirement
from incident_investigator.security.policy import Feature
from incident_investigator.security.storage import latch_safe_mode, local_path, protect_directory

app = typer.Typer(help="Local containment controls. No AWS operations.")
safe = typer.Typer()
features = typer.Typer()
app.add_typer(safe, name="safe-mode")
app.add_typer(features, name="feature")
Directory = Annotated[Path, typer.Option("--data-dir")]
DEFAULT_DIRECTORY = Path(".data/runtime")


@app.command("infrastructure-check")
def infrastructure_check(plan: Annotated[Path, typer.Option("--plan")]) -> None:
    """Inspect Terraform show JSON locally. Never plan, apply or authorize deployment."""
    try:
        path = local_path(plan)
        if not path.is_file():
            raise ValueError("regular_plan_file_required")
        with path.open("rb") as source:
            result = check_plan(source.read(MAX_BYTES + 1))
    except (OSError, ValueError):
        result = PlanCheck(status="blocked", reasons=("plan_unavailable",))
    typer.echo(result.model_dump_json())
    if result.status != "passed":
        raise typer.Exit(3 if result.status == "review_required" else 2)


@app.command("doctor")
def doctor(
    config: Annotated[Path, typer.Option("--config")],
    profile: Annotated[str, typer.Option("--profile")],
    account: Annotated[str, typer.Option("--account")],
    region: Annotated[str, typer.Option("--region")],
    role: Annotated[str, typer.Option("--role")],
) -> None:
    """Inspect local Identity Center configuration; never authenticate or enable live mode."""
    try:
        requirement = IdentityRequirement(
            profile=profile, account_id=account, region=region, collector_role_name=role
        )
        path = local_path(config)
        if not path.is_file():
            raise ValueError("regular_config_file_required")
        with path.open("rb") as source:
            raw = source.read(65_537)
        result = inspect_config(raw, requirement, os.environ)
    except (OSError, ValueError):
        result = DoctorResult(configuration_valid=False, checks=("configuration_unavailable",))
    typer.echo(result.model_dump_json())
    if not result.configuration_valid:
        raise typer.Exit(2)


@contextmanager
def errors() -> Iterator[None]:
    try:
        yield
    except (OSError, sqlite3.Error, ValueError, subprocess.SubprocessError):
        typer.echo(
            "Control unavailable; inspect local storage. No sensitive details logged.", err=True
        )
        raise typer.Exit(2) from None


@safe.command("enable")
def enable(directory: Directory = DEFAULT_DIRECTORY) -> None:
    with errors():
        root = protect_directory(directory)
        latch_safe_mode(root)
        try:
            authority = SecurityAuthority(root)
            authority.change("safe_enable")
        except (OSError, sqlite3.Error):
            if (root / "safe-mode").is_file():
                typer.echo("Safe mode latched; audit persistence failed.", err=True)
                raise typer.Exit(2) from None
            raise
        typer.echo("Safe mode enabled.")


@safe.command("disable")
def disable(directory: Directory = DEFAULT_DIRECTORY) -> None:
    with errors():
        SecurityAuthority(directory).change("safe_disable")
        typer.echo("Safe mode disabled by local operator.")


@features.command("disable")
def disable_feature(feature: Feature, directory: Directory = DEFAULT_DIRECTORY) -> None:
    set_feature(feature, "disable", directory)


@features.command("enable")
def enable_feature(feature: Feature, directory: Directory = DEFAULT_DIRECTORY) -> None:
    set_feature(feature, "enable", directory)


def set_feature(feature: Feature, action: Literal["enable", "disable"], directory: Path) -> None:
    with errors():
        SecurityAuthority(directory).change(action, feature=feature)
        typer.echo("Feature restriction updated; live adapters remain disabled.")


@app.command("status")
def status(directory: Directory = DEFAULT_DIRECTORY) -> None:
    with errors():
        typer.echo(SecurityAuthority(directory).read().model_dump_json())
