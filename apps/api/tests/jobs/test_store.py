import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from incident_investigator.evaluation.golden import IncidentInput
from incident_investigator.jobs.contracts import JobError, JobView
from incident_investigator.jobs.store import JobStore
from incident_investigator.security.authority import SecurityAuthority
from incident_investigator.workflow.replay import prepare
from incident_investigator.workflow.runtime import OfflineRuntime


def incident() -> IncidentInput:
    path = Path("fixtures/evaluation/golden/v1/inputs/case-001.json")
    return IncidentInput.model_validate_json(path.read_bytes())


@pytest.fixture
def store(tmp_path: Path) -> JobStore:
    return JobStore(SecurityAuthority(tmp_path / "runtime"), lambda: 100)


def submit(
    store: JobStore, key: str = "a" * 32, fingerprint: str = "sha256:" + "0" * 64
) -> JobView:
    state, policy = OfflineRuntime(store.authority, store.clock).initialize(prepare(incident()))
    return store.submit(state, policy, key, fingerprint, "operator")


def test_durable_idempotency_and_sanitized_initial_state(store: JobStore) -> None:
    first = submit(store)
    restarted = JobStore(SecurityAuthority(store.authority.root), lambda: 200)
    assert submit(restarted) == first
    assert restarted.recent() == (first,)
    state, policy = restarted.initial(first.id)
    assert state.pin == first.pin and state.report is None
    assert b"CACHE_HOST=cache.internal" not in state.model_dump_json().encode()
    assert policy.id == "offline-investigation-v1"
    assert [event.job for event in restarted.events(first.id, 0)] == [first]
    with pytest.raises(JobError, match="idempotency_conflict"):
        submit(restarted, fingerprint="different")


def test_concurrent_delivery_creates_one_attempt(store: JobStore) -> None:
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: submit(store), range(4)))
    assert len({job.id for job in results}) == 1
    assert len(store.events(results[0].id, 0)) == 1


def test_migration_backup_and_old_checkpoint_reader(store: JobStore) -> None:
    backups = list(store.authority.root.glob("before-jobs-v1-*.sqlite3"))
    assert len(backups) == 1
    with sqlite3.connect(backups[0]) as backup:
        assert backup.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert backup.execute("SELECT COUNT(*) FROM restrictions").fetchone() == (1,)
    runtime = OfflineRuntime(store.authority, store.clock)
    state = runtime.start(incident(), stop_after="scope")
    JobStore(store.authority, store.clock)
    assert runtime.resume(state.attempt_id).report is not None
    assert len(list(store.authority.root.glob("before-jobs-v1-*.sqlite3"))) == 1
    with store.authority.connect() as connection:
        connection.execute("UPDATE job_migrations SET digest='changed'")
    with pytest.raises(ValueError, match="unsupported_job_schema"):
        JobStore(store.authority)


def test_audit_failure_is_atomic_and_health_data_survives(
    store: JobStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*args: object) -> None:
        raise sqlite3.OperationalError("disk full")

    monkeypatch.setattr(store.authority, "_append", fail)
    with pytest.raises(sqlite3.OperationalError):
        submit(store)
    assert store.recent() == ()
    assert store.authority.read().revision == 1


def test_containment_cursor_bounds_and_missing_ids(store: JobStore) -> None:
    job = submit(store)
    with pytest.raises(JobError, match="invalid_event_cursor"):
        store.events(job.id, 9999)
    with pytest.raises(JobError, match="job_not_found"):
        store.get("' OR 1=1 --")
    store.authority.change("safe_enable")
    assert submit(store) == job
    with pytest.raises(JobError, match="contained"):
        submit(store, key="b" * 32)


def test_corrupt_initial_snapshot_is_not_executed(store: JobStore) -> None:
    job = submit(store)
    with store.authority.connect() as connection:
        connection.execute("UPDATE jobs SET initial=? WHERE id=?", (b"{}", job.id))
    with pytest.raises(ValueError):
        store.initial(job.id)
