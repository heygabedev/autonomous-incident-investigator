from concurrent.futures import ThreadPoolExecutor

import pytest
from incident_investigator.memory.contracts import MemoryCase, digest
from incident_investigator.memory.store import MemoryError

from .samples import case, store


def test_case_revisions_are_immutable_and_compare_and_swap_is_atomic() -> None:
    original = case()
    repository = store(original)
    updated = original.model_copy(
        update={
            "revision": 2,
            "parent_digest": digest(original),
            "evaluation_approved": True,
        }
    )
    digest2 = repository.put(updated, digest(original))
    assert repository.read(original.id) == updated
    assert original.evaluation_approved is False
    assert repository.put(updated, digest(original)) == digest2
    with pytest.raises(MemoryError, match="case_conflict"):
        repository.put(original)


def test_concurrent_updates_have_one_winner() -> None:
    original = case()
    repository = store(original)
    a = original.model_copy(
        update={"revision": 2, "parent_digest": digest(original), "evaluation_approved": True}
    )
    b = a.model_copy(update={"runtime_memory_approved": False})

    def update(value: MemoryCase) -> bool:
        try:
            repository.put(value, digest(original))
            return True
        except MemoryError:
            return False

    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(update, (a, b))) == [False, True]


@pytest.mark.parametrize("state", ["revoked", "superseded"])
def test_withdrawal_cannot_be_reversed(state: str) -> None:
    original = case()
    repository = store(original)
    withdrawn = original.model_copy(
        update={
            "revision": 2,
            "parent_digest": digest(original),
            "state": state,
            "runtime_memory_approved": False,
        }
    )
    repository.put(withdrawn, digest(original))
    restored = original.model_copy(update={"revision": 3, "parent_digest": digest(withdrawn)})
    with pytest.raises(MemoryError, match="withdrawal_is_terminal"):
        repository.put(restored, digest(withdrawn))


@pytest.mark.parametrize(
    "change",
    [
        {"revision": 3},
        {"lineage_id": "new"},
        {"duplicate_cluster_id": "new"},
        {"parent_digest": "sha256:" + "0" * 64},
        {"state": "pending", "runtime_memory_approved": False},
    ],
)
def test_invalid_revision_transitions(change: dict[str, object]) -> None:
    original = case()
    repository = store(original)
    updated = original.model_copy(
        update={"revision": 2, "parent_digest": digest(original), **change}
    )
    with pytest.raises(MemoryError):
        repository.put(updated, digest(original))


def test_runtime_and_evaluation_approvals_are_independent() -> None:
    original = case()
    assert original.runtime_memory_approved and not original.evaluation_approved
    with pytest.raises(MemoryError, match="invalid_case"):
        store(original.model_copy(update={"state": "revoked"}))


def test_runbook_revocation_is_current_and_terminal() -> None:
    original = case()
    repository = store(original)
    revoked = original.runbook.model_copy(update={"revision": 2, "state": "revoked"})
    repository.put_runbook(revoked, digest(original.runbook))
    assert repository.runbook(revoked.id).state == "revoked"
    with pytest.raises(MemoryError):
        repository.put_runbook(original.runbook.model_copy(update={"revision": 3}), digest(revoked))
    with pytest.raises(MemoryError):
        repository.runbook("missing")
