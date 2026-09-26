"""Offline replay only. No evaluation labels, AWS credentials or model execution."""

import sqlite3
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated

import typer

from incident_investigator.evaluation.canonical import (
    MAX_BYTES,
    canonical_bytes,
    content_digest,
    parse_json,
)
from incident_investigator.evaluation.golden import IncidentInput
from incident_investigator.security.authority import SecurityAuthority
from incident_investigator.security.policy import OperationDenied
from incident_investigator.security.storage import local_path
from incident_investigator.workflow.contracts import RunState, Stage
from incident_investigator.workflow.runtime import OfflineRuntime

app = typer.Typer(help="Investigate synthetic captured evidence without AWS or model calls.")
Directory = Annotated[Path, typer.Option("--data-dir")]
Stop = Annotated[Stage | None, typer.Option("--stop-after")]
DEFAULT_DIRECTORY = Path(".data/runtime")


@contextmanager
def errors() -> Iterator[None]:
    try:
        yield
    except (OSError, ValueError, sqlite3.Error, OperationDenied, subprocess.SubprocessError):
        typer.echo(
            "Replay refused: invalid input, incompatible checkpoint, or security restriction.",
            err=True,
        )
        raise typer.Exit(2) from None


def emit(state: RunState) -> None:
    typer.echo(
        canonical_bytes(
            {
                "attempt_id": state.attempt_id,
                "next_stage": state.next_stage,
                "pin": state.pin.model_dump(mode="json"),
                "report": state.report.model_dump(mode="json") if state.report else None,
            }
        ).decode()
    )


@app.command("run")
def run(
    source: Path,
    digest: Annotated[str, typer.Option("--digest")],
    directory: Directory = DEFAULT_DIRECTORY,
    stop_after: Stop = None,
    round_limit: Annotated[int, typer.Option("--round-limit", min=0, max=2)] = 2,
) -> None:
    with errors():
        with local_path(source).open("rb") as stream:
            raw = parse_json(stream.read(MAX_BYTES + 1))
        if content_digest(raw) != digest:
            raise ValueError("input_digest_mismatch")
        incident = IncidentInput.model_validate_json(canonical_bytes(raw))
        runtime = OfflineRuntime(SecurityAuthority(directory))
        emit(runtime.start(incident, round_limit=round_limit, stop_after=stop_after))


@app.command("resume")
def resume(
    attempt_id: str, directory: Directory = DEFAULT_DIRECTORY, stop_after: Stop = None
) -> None:
    with errors():
        emit(OfflineRuntime(SecurityAuthority(directory)).resume(attempt_id, stop_after=stop_after))
