import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from incident_investigator.security.authority import SecurityAuthority
from incident_investigator.security.policy import OperationDenied
from incident_investigator.workflow.graph import build_graph, invoke
from incident_investigator.workflow.runtime import OfflineRuntime

from .test_replay import incident


@pytest.fixture
def runtime(tmp_path: Path) -> OfflineRuntime:
    return OfflineRuntime(SecurityAuthority(tmp_path / "runtime"), lambda: 100)


def test_restart_resume_and_completed_idempotency(runtime: OfflineRuntime) -> None:
    paused = runtime.start(incident(), attempt_id="a", stop_after="verify")
    assert paused.report is None
    restarted = OfflineRuntime(SecurityAuthority(runtime.authority.root), lambda: 100)
    resumed = restarted.resume("a")
    assert resumed.report is not None and resumed.report.status == "resolved"
    assert restarted.resume("a") == resumed
    direct = runtime.start(incident(), attempt_id="b")
    assert direct.report is not None
    assert direct.report.model_dump(exclude={"attempt_id"}) == resumed.report.model_dump(
        exclude={"attempt_id"}
    )
    with runtime.authority.connect() as connection:
        rows = connection.execute(
            "SELECT payload FROM workflow_checkpoints WHERE attempt_id='a'"
        ).fetchall()
    assert len(rows) == len(resumed.completed) + 1
    assert b"CACHE_HOST=cache.internal" not in b"".join(row[0] for row in rows)


def test_duplicate_attempt_and_stale_checkpoint_cannot_overwrite(runtime: OfflineRuntime) -> None:
    paused = runtime.start(incident(), attempt_id="same", stop_after="scope")
    with pytest.raises(ValueError, match="attempt_already_exists"):
        runtime.start(incident(), attempt_id="same")
    _, policy = runtime.store.load("same")
    completed = runtime.resume("same")
    with pytest.raises(ValueError, match="checkpoint_conflict"):
        runtime.store.save(completed, policy, expected=paused, now=100)


def test_corruption_and_changed_code_reject_resume(
    runtime: OfflineRuntime, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime.start(incident(), attempt_id="a", stop_after="scope")
    monkeypatch.setattr(
        "incident_investigator.workflow.runtime.runtime_digest", lambda: "sha256:" + "0" * 64
    )
    with pytest.raises(ValueError, match="checkpoint_runtime_mismatch"):
        runtime.resume("a")
    with runtime.authority.connect() as connection:
        connection.execute(
            "UPDATE workflow_checkpoints SET digest=? WHERE attempt_id=?", ("corrupt", "a")
        )
    with pytest.raises(ValueError, match="attempt_unavailable"):
        runtime.resume("a")


def test_revocation_and_safe_mode_apply_to_cached_reports(runtime: OfflineRuntime) -> None:
    state = runtime.start(incident(), attempt_id="a")
    runtime.authority.change("safe_enable")
    with pytest.raises(OperationDenied, match="contained"):
        runtime.resume("a")
    runtime.authority.change("safe_disable")
    runtime.authority.change("revoke", candidate_id=state.pin.candidate_id)
    with pytest.raises(OperationDenied, match="candidate_revoked"):
        runtime.resume("a")


def test_audit_failure_rolls_back_checkpoint(
    runtime: OfflineRuntime, monkeypatch: pytest.MonkeyPatch
) -> None:
    paused = runtime.start(incident(), attempt_id="a", stop_after="scope")

    def fail(*args: object) -> None:
        raise sqlite3.OperationalError("private error")

    monkeypatch.setattr(runtime.authority, "_append", fail)
    with pytest.raises(OperationDenied, match="audit_unavailable"):
        runtime.resume("a")
    assert runtime.store.load("a")[0] == paused


def test_concurrent_resumption_has_one_checkpoint_writer(runtime: OfflineRuntime) -> None:
    paused = runtime.start(incident(), attempt_id="a", stop_after="scope")
    state, policy = runtime.store.load("a")
    from incident_investigator.security.policy import SecurityContext

    context = SecurityContext(
        actor_id="local",
        candidate_id=state.pin.candidate_id,
        policy_id=policy.id,
        account_id=state.incident.account_id,
        region=state.incident.region,
    )
    next_state = invoke(
        build_graph(
            state.pin,
            context,
            policy,
            runtime.authority.broker(policy, lambda: 100),
            stop_after="collect",
        ),
        state,
    )

    def write(_: int) -> bool:
        try:
            runtime.store.save(next_state, policy, expected=paused, now=100)
            return True
        except ValueError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(write, range(2))) == 1


def test_policy_and_schema_corruption_are_rejected(runtime: OfflineRuntime) -> None:
    paused = runtime.start(incident(), attempt_id="a", stop_after="scope")
    _, policy = runtime.store.load("a")
    altered = policy.model_copy(update={"remaining_microdollars": 10})
    with pytest.raises(ValueError, match="checkpoint_policy_mismatch"):
        runtime.store.save(paused, altered, expected=None, now=100)
    with runtime.authority.connect() as connection:
        connection.execute(
            "UPDATE workflow_attempts SET policy=? WHERE attempt_id=?",
            (altered.model_dump_json().encode(), "a"),
        )
    with pytest.raises(ValueError, match="checkpoint_policy_mismatch"):
        runtime.resume("a")


def test_expired_policy_and_checkpoint_audit_failure(
    runtime: OfflineRuntime, monkeypatch: pytest.MonkeyPatch
) -> None:
    paused = runtime.start(incident(), attempt_id="a", stop_after="scope")
    _, policy = runtime.store.load("a")
    expired = OfflineRuntime(runtime.authority, lambda: policy.expires_at)
    with pytest.raises(OperationDenied, match="policy_expired"):
        expired.resume("a")
    assert runtime.store.load("a")[0] == paused
    from incident_investigator.security.policy import SecurityContext

    from .test_graph import execute

    context = SecurityContext(
        actor_id="local",
        candidate_id=paused.pin.candidate_id,
        policy_id=policy.id,
        account_id=paused.incident.account_id,
        region=paused.incident.region,
    )
    next_state = execute(paused, context, policy, stop_after="collect")

    def fail(*args: object) -> None:
        raise sqlite3.OperationalError("disk full")

    monkeypatch.setattr(runtime.authority, "_append", fail)
    with pytest.raises(sqlite3.OperationalError):
        runtime.store.save(next_state, policy, expected=paused, now=100)
    assert runtime.store.load("a")[0] == paused
