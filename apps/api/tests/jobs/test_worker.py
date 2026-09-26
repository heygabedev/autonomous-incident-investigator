import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from incident_investigator.jobs.contracts import JobError, ReplayJob, SubmitJob
from incident_investigator.jobs.service import JobService
from incident_investigator.jobs.store import JobStore
from incident_investigator.jobs.worker import Worker
from incident_investigator.security.authority import SecurityAuthority
from incident_investigator.security.policy import OperationDenied
from incident_investigator.workflow.runtime import OfflineRuntime

from .test_store import incident


@pytest.fixture
def service(tmp_path: Path) -> JobService:
    return JobService(JobStore(SecurityAuthority(tmp_path / "runtime"), lambda: 100))


def enqueue(service: JobService, key: str = "a" * 32):
    return service.submit(SubmitJob(idempotency_key=key, incident=incident()), "operator")


def test_successful_work_has_pinned_progress_and_verified_report(service: JobService) -> None:
    job = enqueue(service)
    assert Worker(service.store).run_once()
    finished = service.store.get(job.id)
    assert finished.status == "succeeded" and finished.report_status == "available"
    assert finished.pin == job.pin and finished.stage == "done"
    events = service.store.events(job.id, 0)
    assert [event.job.revision for event in events] == list(range(1, len(events) + 1))
    assert len({event.job.pin.candidate_digest for event in events}) == 1
    report = json.loads(service.deliver(job.id, "operator"))
    assert report["status"] == "resolved"
    assert report["model_calls"] == 0
    assert len(json.loads(service.deliver(job.id, "operator", evidence=True))) == 3
    assert not Worker(service.store).run_once()


def test_concurrent_workers_only_one_claims(service: JobService) -> None:
    enqueue(service)
    with ThreadPoolExecutor(max_workers=4) as pool:
        claims = list(pool.map(lambda _: Worker(service.store).claim(), range(4)))
    assert sum(claim is not None for claim in claims) == 1


def test_interrupted_checkpoint_resumes_after_lease_expiry(service: JobService) -> None:
    job = enqueue(service)
    worker = Worker(service.store)
    claimed = worker.claim()
    assert claimed is not None
    state, policy = service.store.initial(job.id)
    runtime = OfflineRuntime(
        service.store.authority,
        service.store.clock,
        lambda connection, state: worker.guard(job.id, claimed[1], connection, state),
    )
    paused = runtime.begin(state, policy, stop_after="verify")
    assert paused.report is None
    assert Worker(service.store).claim() is None
    service.store.clock = lambda: 131
    restarted = Worker(service.store)
    newer = restarted.claim()
    assert newer is not None and newer[1] != claimed[1]
    worker.process(*claimed)
    assert service.store.get(job.id).status == "running"
    restarted.process(*newer)
    assert service.store.get(job.id).status == "succeeded"
    assert service.store.get(job.id).dispatch_attempts == 2


def test_cancel_fences_running_checkpoint_and_does_not_overwrite_history(
    service: JobService,
) -> None:
    job = enqueue(service)
    worker = Worker(service.store)
    claimed = worker.claim()
    assert claimed is not None
    cancelled = service.cancel(job.id, "operator")
    worker.process(*claimed)
    assert service.store.get(job.id) == cancelled
    assert service.cancel(job.id, "operator") == cancelled
    with service.store.authority.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM workflow_attempts").fetchone() == (0,)
    with pytest.raises(JobError, match="report_unavailable"):
        service.deliver(job.id, "operator")


def test_recall_and_replay_are_linked_immutable_attempts(service: JobService) -> None:
    job = enqueue(service)
    worker = Worker(service.store)
    worker.run_once()
    original = service.runtime.store.load(job.id)[0]
    recalled = service.recall(job.id, "operator_request", "operator")
    assert recalled.report_status == "recalled"
    with pytest.raises(JobError, match="report_unavailable"):
        service.deliver(job.id, "operator")
    replay = service.replay(job.id, ReplayJob(idempotency_key="b" * 32), "operator")
    assert service.replay(job.id, ReplayJob(idempotency_key="b" * 32), "operator") == replay
    assert replay.id != job.id and replay.replay_of == job.id
    worker.run_once()
    replaced = service.store.get(job.id)
    assert replaced.report_status == "superseded" and replaced.replacement_id == replay.id
    assert replaced.recall_reason == "operator_request"
    assert service.runtime.store.load(job.id)[0] == original
    assert json.loads(service.deliver(replay.id, "operator"))["status"] == "resolved"
    assert service.recall(job.id, "operator_request", "operator") == replaced


def test_replay_is_not_implicit_recall_and_requires_terminal_source(service: JobService) -> None:
    job = enqueue(service)
    with pytest.raises(JobError, match="replay_requires_terminal_job"):
        service.replay(job.id, ReplayJob(idempotency_key="b" * 32), "operator")
    with pytest.raises(JobError, match="report_unavailable"):
        service.recall(job.id, "operator_request", "operator")
    worker = Worker(service.store)
    worker.run_once()
    with pytest.raises(JobError, match="job_already_terminal"):
        service.cancel(job.id, "operator")
    service.replay(job.id, ReplayJob(idempotency_key="b" * 32), "operator")
    worker.run_once()
    assert service.store.get(job.id).report_status == "available"


def test_containment_and_revocation_apply_to_finished_reports(service: JobService) -> None:
    job = enqueue(service)
    authority = service.store.authority
    authority.change("safe_enable")
    assert not Worker(service.store).run_once()
    assert service.deliver(job.id, "operator", evidence=True)
    authority.change("safe_disable")
    Worker(service.store).run_once()
    authority.change("disable", feature="publication")
    with pytest.raises(OperationDenied, match="feature_disabled"):
        service.deliver(job.id, "operator")
    authority.change("revoke", candidate_id=job.pin.candidate_id)
    with pytest.raises(OperationDenied, match="candidate_revoked"):
        service.deliver(job.id, "operator", evidence=True)


def test_revocation_between_claim_and_checkpoint_blocks_job(service: JobService) -> None:
    job = enqueue(service)
    worker = Worker(service.store)
    claimed = worker.claim()
    assert claimed is not None
    service.store.authority.change("revoke", candidate_id=job.pin.candidate_id)
    worker.process(*claimed)
    assert service.store.get(job.id).failure == "restricted"
    with service.store.authority.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM workflow_checkpoints").fetchone() == (0,)


def test_runtime_change_never_silently_resumes(
    service: JobService, monkeypatch: pytest.MonkeyPatch
) -> None:
    job = enqueue(service)
    monkeypatch.setattr(
        "incident_investigator.workflow.runtime.runtime_digest", lambda: "sha256:" + "f" * 64
    )
    Worker(service.store).run_once()
    assert service.store.get(job.id).failure == "incompatible_runtime"


def test_checkpoint_audit_failure_rolls_back_progress(
    service: JobService, monkeypatch: pytest.MonkeyPatch
) -> None:
    job = enqueue(service)
    worker = Worker(service.store)
    claimed = worker.claim()
    assert claimed is not None
    before = service.store.get(job.id)

    def fail(*args: object) -> None:
        raise sqlite3.OperationalError("disk full private text")

    monkeypatch.setattr(service.store.authority, "_append", fail)
    with pytest.raises(sqlite3.OperationalError):
        worker.process(*claimed)
    assert service.store.get(job.id) == before


def test_retry_budget_and_stop_prevent_unbounded_work(service: JobService) -> None:
    job = enqueue(service)
    worker = Worker(service.store)
    for now in (100, 131, 162):
        service.store.clock = lambda now=now: now
        assert worker.claim() is not None
    service.store.clock = lambda: 193
    assert worker.claim() is None
    assert service.store.get(job.id).failure == "execution_failed"
    other = enqueue(service, "b" * 32)
    claimed = worker.claim()
    assert claimed is not None
    worker.stop()
    worker.process(*claimed)
    assert service.store.get(other.id).status == "running"


def test_background_worker_shutdown(service: JobService) -> None:
    worker = Worker(service.store)
    worker.start()
    with pytest.raises(RuntimeError, match="worker_already_started"):
        worker.start()
    worker.stop()
    assert worker.thread is not None and not worker.thread.is_alive()
