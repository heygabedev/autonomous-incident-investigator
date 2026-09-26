import json
from pathlib import Path

from incident_investigator.security.authority import SecurityAuthority
from incident_investigator.workflow.cli import app
from typer.testing import CliRunner

from .test_replay import GOLDEN, MEMBERS


def test_cli_run_resume_and_revoked_export(tmp_path: Path) -> None:
    runner = CliRunner()
    options = ["--data-dir", str(tmp_path / "runtime")]
    member = MEMBERS[0]
    result = runner.invoke(
        app,
        [
            "run",
            str(GOLDEN / "inputs" / "case-001.json"),
            "--digest",
            member["input_digest"],
            "--stop-after",
            "verify",
            *options,
        ],
    )
    assert result.exit_code == 0, result.output
    paused = json.loads(result.stdout)
    assert paused["report"] is None
    result = runner.invoke(app, ["resume", paused["attempt_id"], *options])
    assert result.exit_code == 0, result.output
    completed = json.loads(result.stdout)
    assert completed["report"]["status"] == "resolved"
    assert completed["pin"] == paused["pin"]
    SecurityAuthority(tmp_path / "runtime").change("safe_enable")
    denied = runner.invoke(app, ["resume", paused["attempt_id"], *options])
    assert denied.exit_code == 2 and "recommendations" not in denied.output


def test_cli_rejects_wrong_digest_labels_and_invalid_attempt(tmp_path: Path) -> None:
    runner = CliRunner()
    options = ["--data-dir", str(tmp_path / "runtime")]
    for path, digest in (
        (GOLDEN / "inputs" / "case-001.json", "sha256:" + "0" * 64),
        (GOLDEN / "labels" / "case-001.json", MEMBERS[0]["labels_digest"]),
    ):
        result = runner.invoke(app, ["run", str(path), "--digest", digest, *options])
        assert result.exit_code == 2 and "Replay refused" in result.output
        assert "expected_status" not in result.output
    result = runner.invoke(app, ["resume", "x' OR 1=1 --", *options])
    assert result.exit_code == 2 and "OR 1=1" not in result.output
