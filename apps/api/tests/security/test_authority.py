import json
import os
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from incident_investigator.security.authority import AuditEvent, SecurityAuthority
from incident_investigator.security.cli import app
from incident_investigator.security.evidence import RawEvidence, sanitize
from incident_investigator.security.policy import OperationDenied
from incident_investigator.security.storage import local_path, private_file, protect_directory
from typer.testing import CliRunner

from .test_policy import CONTEXT, policy, request


@pytest.fixture
def authority(tmp_path: Path) -> SecurityAuthority:
    return SecurityAuthority(tmp_path / "private")


def test_persistent_controls_and_revocations(authority: SecurityAuthority) -> None:
    assert not authority.read().safe_mode
    authority.change("safe_enable")
    assert authority.read().safe_mode
    assert SecurityAuthority(authority.root).read().safe_mode
    authority.change("safe_disable")
    for feature in ("collection", "model", "history", "publication"):
        authority.change("disable", feature=feature)  # type: ignore[arg-type]
        assert feature in authority.read().disabled_features
        authority.change("enable", feature=feature)  # type: ignore[arg-type]
        assert feature not in authority.read().disabled_features
    authority.change("revoke", candidate_id=CONTEXT.candidate_id)
    with pytest.raises(OperationDenied, match="candidate_revoked"):
        authority.broker(policy(), lambda: 0).dispatch(CONTEXT, request(), policy(), lambda _: None)


def test_environment_override_is_latched(
    authority: SecurityAuthority, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("INCIDENT_AGENT_SAFE_MODE", "1")
    assert authority.read().safe_mode
    with pytest.raises(ValueError, match="environment_containment_active"):
        authority.change("safe_disable")
    monkeypatch.delenv("INCIDENT_AGENT_SAFE_MODE")
    assert authority.read().safe_mode
    authority.change("safe_disable")
    assert not authority.read().safe_mode


def test_audit_before_dispatch_and_no_sensitive_payloads(authority: SecurityAuthority) -> None:
    broker = authority.broker(policy(), lambda: 0)

    def handler(_: Any) -> str:
        with authority.connect() as connection:
            rows = connection.execute("SELECT payload FROM audit").fetchall()
        assert len(rows) == 1
        event = json.loads(rows[0][0])
        assert event["action"] == "report.publish"
        assert "fixture-1" not in rows[0][0].decode()
        return "done"

    assert broker.dispatch(CONTEXT, request(), policy(), handler) == "done"


def test_audit_failure_blocks_operations_but_can_latch(
    authority: SecurityAuthority,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: Any) -> None:
        raise sqlite3.OperationalError("disk full private detail")

    monkeypatch.setattr(authority, "_append", fail)
    with pytest.raises(OperationDenied, match="audit_unavailable"):
        authority.broker(policy(), lambda: 0).dispatch(
            CONTEXT, request(), policy(), lambda _: pytest.fail()
        )
    with pytest.raises(sqlite3.OperationalError):
        authority.change("safe_enable")
    assert authority.read().safe_mode
    with pytest.raises(sqlite3.OperationalError):
        authority.change("safe_disable")
    assert authority.read().safe_mode


def test_control_transaction_rolls_back_and_concurrent_changes_survive(
    authority: SecurityAuthority,
) -> None:
    revision = authority.read().revision
    with pytest.raises(ValueError):
        authority.change("disable")
    assert authority.read().revision == revision

    def revoke(i: int) -> None:
        authority.change("revoke", candidate_id=f"candidate-{i}")

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(revoke, range(10)))
    assert len(authority.read().revoked_candidates) == 10
    assert authority.read().revision == revision + 10


def test_sanitized_opaque_artifacts_and_tamper_detection(authority: SecurityAuthority) -> None:
    account, region, resources = "000000000000", "eu-central-1", ("fixture-1",)
    evidence = sanitize(
        RawEvidence(
            account,
            region,
            resources[0],
            {
                "status": "failed",
                "message": "password=private",
            },
        ),
        account,
        region,
        resources,
    ).evidence
    assert evidence is not None
    identifier = authority.put_evidence((evidence,), account, region, resources, "local")
    result = authority.export_evidence(identifier, account, region, resources, "local")
    assert b"password" not in result
    assert evidence.id.encode() in result
    for malicious in ("../secret", "C:/private", "\\\\remote\\share", "x' OR 1=1 --"):
        with pytest.raises(ValueError, match="invalid_artifact_id"):
            authority.export_evidence(malicious, account, region, resources, "local")
    with pytest.raises(ValueError):
        authority.export_evidence(identifier, "111111111111", region, resources, "local")
    with authority.connect() as connection:
        connection.execute("UPDATE evidence SET payload=? WHERE id=?", (b"[]", identifier))
    with pytest.raises(ValueError, match="artifact_integrity_failure"):
        authority.export_evidence(identifier, account, region, resources, "local")


def test_invalid_audit_and_permission_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError):
        AuditEvent(
            actor_id="local",
            action="read",
            decision="allow",
            reason="ok",
            policy_revision=1,
            raw="password=secret",
        )

    def fail(_: Path) -> Path:
        raise OSError("permission unavailable")

    monkeypatch.setattr("incident_investigator.security.authority.protect_directory", fail)
    with pytest.raises(OSError):
        SecurityAuthority(tmp_path)


def test_reject_links_traversal_and_network_paths(tmp_path: Path) -> None:
    for path in (tmp_path / ".." / "outside", Path("//host/share/data")):
        with pytest.raises(ValueError):
            local_path(path)
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        if sys.platform != "win32":
            raise
        # Windows developer mode is not required: directory junctions also escape roots.
        import subprocess

        subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "New-Item -ItemType Junction -Path $env:TEST_LINK "
                "-Target $env:TEST_TARGET | Out-Null",
            ],
            env={**os.environ, "TEST_LINK": str(link), "TEST_TARGET": str(target)},
            check=True,
        )
    with pytest.raises(ValueError):
        local_path(link / "child")


def test_private_storage_permissions(tmp_path: Path) -> None:
    root = protect_directory(tmp_path / "private")
    path = private_file(root / "file")
    if sys.platform != "win32":
        assert root.stat().st_mode & 0o777 == 0o700
        assert path.stat().st_mode & 0o777 == 0o600
        path.chmod(0o644)
        with pytest.raises(OSError):
            private_file(path)
    else:
        # protect_directory verifies the native DACL, not chmod.
        assert protect_directory(root) == root


def test_cli_controls_and_corrupt_store_containment(tmp_path: Path) -> None:
    runner = CliRunner()
    directory = tmp_path / "runtime"
    options = ["--data-dir", str(directory)]
    assert runner.invoke(app, ["safe-mode", "enable", *options]).exit_code == 0
    assert json.loads(runner.invoke(app, ["status", *options]).stdout)["safe_mode"]
    assert runner.invoke(app, ["feature", "disable", "model", *options]).exit_code == 0
    assert runner.invoke(app, ["safe-mode", "disable", *options]).exit_code == 0
    (directory / "security.sqlite3").write_bytes(b"corrupt store")
    result = runner.invoke(app, ["safe-mode", "enable", *options])
    assert result.exit_code == 2
    assert (directory / "safe-mode").exists()
    assert "audit persistence failed" in result.output
