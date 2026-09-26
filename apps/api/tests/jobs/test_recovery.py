import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from incident_investigator.evaluation.canonical import content_digest, parse_json
from incident_investigator.jobs.contracts import JobError, ReplayJob
from incident_investigator.jobs.schema import STATEMENTS
from incident_investigator.jobs.service import JobService
from incident_investigator.jobs.store import JobStore, encoded
from incident_investigator.jobs.worker import Worker
from incident_investigator.main import create_app
from incident_investigator.security.authority import SecurityAuthority
from incident_investigator.security.sessions import Sessions

from .test_api import ROOT, payload
from .test_store import submit


def test_capacity_is_bounded_and_returns_retry_after(tmp_path: Path) -> None:
    sessions = Sessions()
    token = sessions.redeem(sessions.issue_pairing())
    application = create_app(
        sessions=sessions, authority=SecurityAuthority(tmp_path / "runtime"), start_worker=False
    )
    with TestClient(
        application, base_url="http://127.0.0.1:8000", headers={"Authorization": f"Bearer {token}"}
    ) as client:
        for index in range(32):
            assert client.post(ROOT, json=payload(f"{index:032x}")).status_code == 202
        full = client.post(ROOT, json=payload("f" * 32))
        assert full.status_code == 429 and int(full.headers["retry-after"]) > 0
        assert len(client.get(ROOT).json()) == 32
        original = client.post(ROOT, json=payload("0" * 32))
        assert original.status_code == 202  # Duplicate delivery consumes no extra capacity.
        assert client.delete(f"{ROOT}/{original.json()['id']}").status_code == 200
        assert client.post(ROOT, json=payload("f" * 32)).status_code == 202


def test_interrupted_migration_rolls_back_and_can_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = SecurityAuthority(tmp_path / "runtime")
    with monkeypatch.context() as patch:
        patch.setattr("incident_investigator.jobs.schema.STATEMENTS", (*STATEMENTS, "INVALID SQL"))
        with pytest.raises(sqlite3.OperationalError):
            JobStore(authority)
    with authority.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM job_migrations").fetchone() == (0,)
        assert not connection.execute("SELECT name FROM sqlite_master WHERE name='jobs'").fetchall()
    restarted = JobStore(SecurityAuthority(authority.root))
    assert restarted.recent() == ()
    assert len(list(authority.root.glob("before-jobs-v1-*.sqlite3"))) == 2


def test_backup_restores_to_new_store_without_touching_failed_source(tmp_path: Path) -> None:
    authority = SecurityAuthority(tmp_path / "source")
    authority.change("revoke", candidate_id="revoked-before-migration")
    store = JobStore(authority, lambda: 100)
    job = submit(store)
    backup = next(authority.root.glob("before-jobs-v1-*.sqlite3"))
    restored = SecurityAuthority(tmp_path / "restored")
    with sqlite3.connect(backup) as source, restored.connect() as target:
        source.backup(target)
    # A restore must reconcile newer revocations before any cutover. No cutover API exists.
    authority.change("revoke", candidate_id="revoked-after-backup")
    for identifier in authority.read().revoked_candidates:
        if identifier not in restored.read().revoked_candidates:
            restored.change("revoke", candidate_id=identifier)
    assert restored.read().revoked_candidates == authority.read().revoked_candidates
    with restored.connect() as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        restored_policy = connection.execute("SELECT payload FROM restrictions").fetchone()[0]
    with authority.connect() as connection:
        current_policy = connection.execute("SELECT payload FROM restrictions").fetchone()[0]
    assert content_digest(parse_json(restored_policy)) == content_digest(parse_json(current_policy))
    assert store.get(job.id).id == job.id
    assert JobStore(restored).recent() == ()


def test_corrupt_report_and_poisoned_event_are_rejected(tmp_path: Path) -> None:
    store = JobStore(SecurityAuthority(tmp_path / "runtime"), lambda: 100)
    service = JobService(store)
    job = submit(store)
    Worker(store).run_once()
    state, _ = service.runtime.store.load(job.id)
    assert state.report is not None
    forged = state.model_copy(
        update={"report": state.report.model_copy(update={"evidence_ids": ("invented",)})}
    )
    with store.authority.connect() as connection:
        digest = content_digest(parse_json(forged.model_dump_json()))
        connection.execute(
            "UPDATE workflow_checkpoints SET payload=?, digest=? WHERE attempt_id=? AND step=?",
            (encoded(forged), digest, job.id, len(state.completed)),
        )
        connection.execute(
            "UPDATE workflow_attempts SET head_digest=? WHERE attempt_id=?", (digest, job.id)
        )
    with pytest.raises(ValueError):
        service.deliver(job.id, "operator")
    with store.authority.connect() as connection:
        connection.execute(
            "UPDATE job_events SET payload=? WHERE job_id=?", (b'{"raw":"private"}', job.id)
        )
    with pytest.raises(ValueError):
        store.events(job.id, 0)


def test_lease_expiry_and_containment_during_node_fence(tmp_path: Path) -> None:
    store = JobStore(SecurityAuthority(tmp_path / "runtime"), lambda: 100)
    job = submit(store)
    worker = Worker(store)
    claim = worker.claim()
    assert claim is not None
    state, _ = store.initial(job.id)
    store.clock = lambda: 130
    with store.authority.connect() as connection, pytest.raises(JobError, match="lease_lost"):
        worker.guard(job.id, claim[1], connection, state)
    assert store.get(job.id).completed_steps == 0
    newer = worker.claim()
    assert newer is not None
    store.authority.change("safe_enable")
    worker.process(*newer)
    assert store.get(job.id).failure == "restricted"


def test_application_restart_revokes_browser_not_job_history(tmp_path: Path) -> None:
    authority = SecurityAuthority(tmp_path / "runtime")
    sessions = Sessions()
    token = sessions.redeem(sessions.issue_pairing())
    app = create_app(sessions=sessions, authority=authority, start_worker=False)
    with TestClient(
        app, base_url="http://127.0.0.1:8000", headers={"Authorization": f"Bearer {token}"}
    ) as browser:
        job = browser.post(ROOT, json=payload()).json()
    replacement = Sessions()
    app = create_app(
        sessions=replacement, authority=SecurityAuthority(authority.root), start_worker=False
    )
    with TestClient(
        app, base_url="http://127.0.0.1:8000", headers={"Authorization": f"Bearer {token}"}
    ) as browser:
        assert browser.get(ROOT).status_code == 401
        browser.headers["Authorization"] = "Bearer " + replacement.redeem(
            replacement.issue_pairing()
        )
        assert browser.get(ROOT).json() == [job]


@pytest.mark.parametrize("reason", ["security_review", "invalidated_evidence", "defective_runtime"])
def test_recall_cannot_be_bypassed_by_replay(tmp_path: Path, reason: str) -> None:
    store = JobStore(SecurityAuthority(tmp_path / "runtime"), lambda: 100)
    service = JobService(store)
    job = submit(store)
    Worker(store).run_once()
    service.recall(job.id, reason, "operator")
    with pytest.raises(JobError, match="replay_"):
        service.replay(job.id, ReplayJob(idempotency_key="b" * 32), "operator")
    if reason == "security_review":
        with pytest.raises(JobError, match="evidence_quarantined"):
            service.deliver(job.id, "operator", evidence=True)
    assert service.store.recent()[0].id == job.id


def test_source_revocation_and_later_quarantine_apply_to_descendants(tmp_path: Path) -> None:
    store = JobStore(SecurityAuthority(tmp_path / "runtime"), lambda: 100)
    service = JobService(store)
    job = submit(store)
    worker = Worker(store)
    worker.run_once()
    child = service.replay(job.id, ReplayJob(idempotency_key="b" * 32), "operator")
    worker.run_once()
    service.recall(job.id, "operator_request", "operator")
    service.recall(job.id, "security_review", "operator")
    assert service.recall(job.id, "operator_request", "operator").recall_reason == "security_review"
    with pytest.raises(JobError, match="replay_source_restricted"):
        service.deliver(child.id, "operator")
    with pytest.raises(JobError, match="replay_source_restricted"):
        service.replay(child.id, ReplayJob(idempotency_key="c" * 32), "operator")
    # Even when a new policy timestamp changes the offline candidate ID, a source
    # revocation cannot be escaped by laundering captured input into a fresh attempt.
    other = submit(store, key="d" * 32)
    worker.run_once()
    store.authority.change("revoke", candidate_id=other.pin.candidate_id)
    service.runtime.clock = lambda: 200
    with pytest.raises(JobError, match="replay_source_restricted"):
        service.replay(other.id, ReplayJob(idempotency_key="e" * 32), "operator")
