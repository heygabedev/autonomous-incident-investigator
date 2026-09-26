import json
from pathlib import Path

import pytest
from incident_investigator.evaluation.artifacts import seal
from incident_investigator.evaluation.canonical import MAX_BYTES, parse_json
from incident_investigator.evaluation.cli import app, schema_documents
from incident_investigator.evaluation.registry import SQLiteRegistry
from typer.testing import CliRunner

from .factories import artifact, payload
from .test_registry import register

runner = CliRunner()


def test_fingerprint_without_registry(tmp_path: Path) -> None:
    manifest = tmp_path / "candidate.json"
    manifest.write_text(json.dumps(payload()), encoding="utf-8")
    result = runner.invoke(app, ["candidate", "fingerprint", str(manifest)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["candidate"]["digest"] == seal(artifact()).digest
    assert sorted(p.name for p in tmp_path.iterdir()) == ["candidate.json"]


def test_registry_roundtrip(tmp_path: Path) -> None:
    manifest = tmp_path / "candidate.json"
    manifest.write_text(json.dumps(payload()), encoding="utf-8")
    store = tmp_path / "registry.sqlite3"
    options = ["--store", str(store)]
    assert runner.invoke(app, ["registry", "init", *options]).exit_code == 0
    result = runner.invoke(app, ["registry", "register", str(manifest), *options])
    assert result.exit_code == 0, result.output
    digest = json.loads(result.output)["digest"]
    result = runner.invoke(app, ["registry", "inspect", digest, *options])
    assert result.exit_code == 0
    assert json.loads(result.output)["payload"]["kind"] == "candidate_bundle"
    result = runner.invoke(app, ["candidate", "validate", digest, *options])
    assert result.exit_code == 0
    assert json.loads(result.output)["promotion_qualified"] is False


def test_dataset_commands(tmp_path: Path) -> None:
    store = SQLiteRegistry(tmp_path / "registry.sqlite3")
    store.initialize()
    case = register(store, payload("case_revision"))
    dataset = payload("dataset_snapshot")
    dataset["members"][0]["case"] = case.model_dump(mode="json")
    reference = register(store, dataset)
    for command in ("inspect", "validate"):
        result = runner.invoke(
            app, ["dataset", command, reference.digest, "--store", str(store.path)]
        )
        assert result.exit_code == 0, result.output
    assert json.loads(result.output)["frozen_by_command"] is False
    candidate = register(store, payload())
    result = runner.invoke(
        app, ["dataset", "inspect", candidate.digest, "--store", str(store.path)]
    )
    assert result.exit_code == 2


@pytest.mark.parametrize(
    "content",
    [b'{"secret":"do-not-echo-me"}', b'{"id":1,"id":2}', b"x" * (MAX_BYTES + 1)],
    ids=["unknown-field", "duplicate-key", "oversized"],
)
def test_bad_input_fails_without_echo(tmp_path: Path, content: bytes) -> None:
    manifest = tmp_path / "invalid.json"
    manifest.write_bytes(content)
    result = runner.invoke(app, ["candidate", "fingerprint", str(manifest)])
    assert result.exit_code == 2
    assert "do-not-echo-me" not in result.output
    assert "Traceback" not in result.output


def test_wrong_fingerprint_kind(tmp_path: Path) -> None:
    manifest = tmp_path / "case.json"
    manifest.write_text(json.dumps(payload("case_revision")), encoding="utf-8")
    assert runner.invoke(app, ["candidate", "fingerprint", str(manifest)]).exit_code == 2


def test_missing_registry_inspection_has_no_side_effect(tmp_path: Path) -> None:
    store = tmp_path / "absent.sqlite3"
    result = runner.invoke(app, ["registry", "inspect", "unknown", "--store", str(store)])
    assert result.exit_code == 2
    assert not store.exists()


def test_schema_export_reproducible_and_non_overwriting(tmp_path: Path) -> None:
    args = ["schema", "export", "--output", str(tmp_path)]
    assert runner.invoke(app, args).exit_code == 0
    assert runner.invoke(app, args).exit_code == 0
    for name, expected in schema_documents().items():
        assert parse_json((tmp_path / name).read_bytes()) == expected
    target = tmp_path / "artifact.schema.json"
    target.write_text("existing user data", encoding="utf-8")
    assert runner.invoke(app, args).exit_code == 2
    assert target.read_text(encoding="utf-8") == "existing user data"


def test_checked_in_schemas_are_current() -> None:
    root = Path(__file__).resolve().parents[4]
    for name, expected in schema_documents().items():
        assert parse_json((root / "schemas" / "evaluation" / name).read_bytes()) == expected


@pytest.mark.parametrize("command", ["run", "compare", "promotion-check"])
def test_unimplemented_authority_is_not_exposed(command: str) -> None:
    assert runner.invoke(app, [command]).exit_code == 2
