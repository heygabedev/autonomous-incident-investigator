"""In-memory canonical store for synthetic development tests, not DynamoDB.

An index cannot update this store. Revisions use compare-and-swap and revoked
identities cannot be resurrected. Production case governance remains deferred.
"""

from threading import RLock

from incident_investigator.memory.contracts import MemoryCase, Runbook, digest


class MemoryError(ValueError):
    pass


class FixtureCaseStore:
    def __init__(self) -> None:
        self._lock = RLock()
        self._heads: dict[str, str] = {}
        self._revisions: dict[str, MemoryCase] = {}
        self._runbooks: dict[str, Runbook] = {}

    def put_runbook(self, book: Runbook, expected_digest: str | None = None) -> str:
        book = Runbook.model_validate_json(book.model_dump_json())
        with self._lock:
            old = self._runbooks.get(book.id)
            if old == book:
                return digest(book)
            if (digest(old) if old else None) != expected_digest:
                raise MemoryError("runbook_conflict")
            if old is None:
                if book.revision != 1 or len(self._runbooks) >= 1000:
                    raise MemoryError("runbook_initial_revision_or_capacity")
            elif old.state in ("revoked", "superseded") or book.revision != old.revision + 1:
                raise MemoryError("runbook_revision_or_withdrawal")
            self._runbooks[book.id] = book
            return digest(book)

    def runbook(self, book_id: str) -> Runbook:
        with self._lock:
            if book_id not in self._runbooks:
                raise MemoryError("runbook_unavailable")
            return Runbook.model_validate_json(self._runbooks[book_id].model_dump_json())

    def put(self, case: MemoryCase, expected_digest: str | None = None) -> str:
        try:
            case = MemoryCase.model_validate_json(case.model_dump_json())
        except ValueError:
            raise MemoryError("invalid_case") from None
        current_digest = digest(case)
        with self._lock:
            head = self._heads.get(case.id)
            if head == current_digest:
                return current_digest
            if head != expected_digest:
                raise MemoryError("case_conflict")
            if head is None:
                if case.revision != 1 or len(self._heads) >= 1000:
                    raise MemoryError("initial_revision_or_capacity")
            else:
                old = self._revisions[head]
                if old.state in ("revoked", "superseded"):
                    raise MemoryError("withdrawal_is_terminal")
                if case.revision != old.revision + 1 or case.parent_digest != head:
                    raise MemoryError("revision_chain")
                if case.revision_created_at < old.revision_created_at:
                    raise MemoryError("revision_time_regression")
                if (case.lineage_id, case.duplicate_cluster_id) != (
                    old.lineage_id,
                    old.duplicate_cluster_id,
                ):
                    raise MemoryError("lineage_changed")
                if old.state == "verified" and case.state == "pending":
                    raise MemoryError("lifecycle_regression")
            if len(self._revisions) >= 10000:
                raise MemoryError("revision_capacity")
            self._revisions[current_digest] = case
            self._heads[case.id] = current_digest
            return current_digest

    def read(self, case_id: str) -> MemoryCase:
        with self._lock:
            head = self._heads.get(case_id)
            if head is None:
                raise MemoryError("case_unavailable")
            case = MemoryCase.model_validate_json(self._revisions[head].model_dump_json())
            if case.id != case_id or digest(case) != head:
                raise MemoryError("case_integrity")
            return case

    def snapshot(self) -> tuple[MemoryCase, ...]:
        with self._lock:
            return tuple(self.read(case_id) for case_id in sorted(self._heads))
