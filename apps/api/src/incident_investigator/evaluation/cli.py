"""Offline metadata tooling. No candidate execution or promotion authority."""

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from sqlite3 import Error as SQLiteError
from typing import Annotated, Any

import typer

from incident_investigator.evaluation.artifacts import (
    ARTIFACT_ADAPTER,
    ArtifactEnvelope,
    parse_artifact,
    retrieval_fingerprint,
    seal,
)
from incident_investigator.evaluation.canonical import MAX_BYTES, canonical_bytes
from incident_investigator.evaluation.golden import (
    ExpectedAnswer,
    GoldenManifest,
    IncidentInput,
    validate_golden_dataset,
)
from incident_investigator.evaluation.models import CandidateBundle, DatasetSnapshot
from incident_investigator.evaluation.registry import SQLiteRegistry
from incident_investigator.evaluation.validation import (
    RegisteredDatasets,
    validate_candidate_links,
)

app = typer.Typer(help="Offline evaluation metadata tools; no execution or promotion.")
registry_app = typer.Typer(help="Explicit initialization and append-only registration.")
candidate_app = typer.Typer(help="Candidate identities and metadata links.")
dataset_app = typer.Typer(help="Synthetic dataset metadata; real-case approval is not enabled.")
schema_app = typer.Typer(help="Generate JSON Schema contracts.")
golden_app = typer.Typer(help="Validate public synthetic development fixtures.")
app.add_typer(registry_app, name="registry")
app.add_typer(candidate_app, name="candidate")
app.add_typer(dataset_app, name="dataset")
app.add_typer(schema_app, name="schema")
app.add_typer(golden_app, name="golden")

StoreOption = Annotated[Path, typer.Option("--store", help="Local metadata SQLite path.")]
DEFAULT_STORE = Path(".data/evaluation/registry.sqlite3")


@contextmanager
def errors() -> Iterator[None]:
    try:
        yield
    except (OSError, SQLiteError, ValueError) as exc:
        # Validation exceptions can contain complete input values. Never print them.
        typer.echo(
            "error: invalid input, unavailable registry, or failed metadata checks", err=True
        )
        raise typer.Exit(code=2) from exc


def emit(value: Any) -> None:
    typer.echo(canonical_bytes(value).decode("utf-8"))


def read_manifest(path: Path) -> bytes:
    with path.open("rb") as stream:
        return stream.read(MAX_BYTES + 1)


@registry_app.command("init")
def initialize(store: StoreOption = DEFAULT_STORE) -> None:
    with errors():
        SQLiteRegistry(store).initialize()
        emit({"status": "initialized"})


@registry_app.command("register")
def register(manifest: Path, store: StoreOption = DEFAULT_STORE) -> None:
    """Register a payload manifest, not an envelope or an approval."""
    with errors():
        reference = SQLiteRegistry(store).put(seal(parse_artifact(read_manifest(manifest))))
        emit(reference.model_dump(mode="json"))


@registry_app.command("inspect")
def inspect(digest: str, store: StoreOption = DEFAULT_STORE) -> None:
    with errors():
        emit(SQLiteRegistry(store).get(digest).model_dump(mode="json"))


@candidate_app.command("fingerprint")
def fingerprint(manifest: Path) -> None:
    with errors():
        candidate = parse_artifact(read_manifest(manifest))
        if not isinstance(candidate, CandidateBundle):
            raise ValueError("expected candidate")
        emit(
            {
                "candidate": seal(candidate).reference().model_dump(mode="json"),
                "retrieval_fingerprint": retrieval_fingerprint(candidate.retrieval),
            }
        )


@candidate_app.command("validate")
def candidate_validate(digest: str, store: StoreOption = DEFAULT_STORE) -> None:
    with errors():
        registry = SQLiteRegistry(store)
        validate_candidate_links(registry, registry.get(digest).reference())
        emit({"status": "metadata_valid", "digest": digest, "promotion_qualified": False})


@dataset_app.command("validate")
def dataset_validate(digest: str, store: StoreOption = DEFAULT_STORE) -> None:
    with errors():
        registry = SQLiteRegistry(store)
        cases = RegisteredDatasets(registry).validate(registry.get(digest).reference())
        emit({"status": "metadata_valid", "case_count": len(cases), "frozen_by_command": False})


@dataset_app.command("inspect")
def dataset_inspect(digest: str, store: StoreOption = DEFAULT_STORE) -> None:
    with errors():
        envelope = SQLiteRegistry(store).get(digest)
        if not isinstance(envelope.payload, DatasetSnapshot):
            raise ValueError("expected dataset")
        emit(envelope.model_dump(mode="json"))


def schema_documents() -> dict[str, Any]:
    return {
        "artifact.schema.json": ARTIFACT_ADAPTER.json_schema(),
        "envelope.schema.json": ArtifactEnvelope.model_json_schema(),
        "golden-input.schema.json": IncidentInput.model_json_schema(),
        "golden-answer.schema.json": ExpectedAnswer.model_json_schema(),
        "golden-manifest.schema.json": GoldenManifest.model_json_schema(),
    }


@golden_app.command("validate")
def golden_validate(directory: Path) -> None:
    with errors():
        manifest = validate_golden_dataset(directory)
        emit(
            {
                "status": "fixtures_valid",
                "dataset_id": manifest.dataset_id,
                "version": manifest.version,
                "case_count": len(manifest.members),
                "lineage_count": len({member.lineage_id for member in manifest.members}),
                "promotion_eligible": manifest.promotion_eligible,
            }
        )


@schema_app.command("export")
def export(output: Annotated[Path, typer.Option("--output")]) -> None:
    """Generate schemas into a directory; never overwrite differing files."""
    with errors():
        documents = {
            name: canonical_bytes(value) + b"\n" for name, value in schema_documents().items()
        }
        # Check every collision before creating any outputs.
        for name, content in documents.items():
            target = output / name
            if target.exists() and read_manifest(target) != content:
                raise ValueError("schema output differs; choose a new directory")
        output.mkdir(parents=True, exist_ok=True)
        for name, content in documents.items():
            target = output / name
            try:
                with target.open("xb") as stream:
                    stream.write(content)
            except FileExistsError:
                if read_manifest(target) != content:
                    raise ValueError("schema output changed concurrently") from None
        emit({"status": "exported", "files": sorted(documents)})
