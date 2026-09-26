import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from incident_investigator.evaluation.artifacts import parse_artifact, seal
from incident_investigator.evaluation.models import ArtifactRef
from incident_investigator.evaluation.registry import (
    IdentityConflict,
    IntegrityError,
    NotFound,
    SQLiteRegistry,
)

from .factories import artifact, payload


@pytest.fixture
def registry(tmp_path: Path) -> SQLiteRegistry:
    store = SQLiteRegistry(tmp_path / "metadata.sqlite3")
    store.initialize()
    return store


def register(store: SQLiteRegistry, value: dict[str, Any]) -> ArtifactRef:
    return store.put(seal(parse_artifact(json.dumps(value))))


def test_roundtrip_and_idempotency(registry: SQLiteRegistry) -> None:
    envelope = seal(artifact())
    reference = registry.put(envelope)
    assert registry.put(envelope) == reference
    assert registry.resolve(reference) == envelope
    registry.initialize()
    assert registry.list_kind("candidate_bundle") == (envelope,)


def test_conflicting_identity_never_overwrites(registry: SQLiteRegistry) -> None:
    first = register(registry, payload())
    changed = payload()
    changed["budgets"]["model_calls"] = 7
    with pytest.raises(IdentityConflict):
        register(registry, changed)
    assert registry.resolve(first).payload == artifact()
    changed["version"] = "1.0.1"
    assert register(registry, changed).digest != first.digest


def test_concurrent_idempotent_registration(registry: SQLiteRegistry) -> None:
    envelope = seal(artifact())
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: registry.put(envelope), range(24)))
    assert len(set(ref.digest for ref in results)) == 1
    assert len(registry.list_kind("candidate_bundle")) == 1


def test_concurrent_conflicting_registration(registry: SQLiteRegistry) -> None:
    def attempt(number: int) -> str:
        value = payload()
        value["budgets"]["model_calls"] = number
        try:
            return register(registry, value).digest
        except IdentityConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(1, 9)))
    assert results.count("conflict") == 7
    assert len(registry.list_kind("candidate_bundle")) == 1


@pytest.mark.parametrize(
    "column,value", [("envelope", b"{}"), ("kind", "exposure"), ("id", "changed")]
)
def test_corruption_is_detected(registry: SQLiteRegistry, column: str, value: str | bytes) -> None:
    reference = registry.put(seal(artifact()))
    with sqlite3.connect(registry.path) as connection:
        # Column names come only from the fixed parametrization above.
        connection.execute(f"UPDATE artifacts SET {column} = ?", (value,))
    with pytest.raises(IntegrityError):
        registry.get(reference.digest)
    with pytest.raises(IntegrityError):
        registry.list_kind("invalidation")


def test_reference_alias_is_rejected(registry: SQLiteRegistry) -> None:
    reference = registry.put(seal(artifact()))
    with pytest.raises(IntegrityError):
        registry.resolve(reference.model_copy(update={"id": "different"}))


def test_read_missing_does_not_create_database(tmp_path: Path) -> None:
    store = SQLiteRegistry(tmp_path / "absent.sqlite3")
    with pytest.raises(NotFound):
        store.get("sha256:" + "a" * 64)
    assert not store.path.exists()


def test_unknown_digest(registry: SQLiteRegistry) -> None:
    with pytest.raises(NotFound):
        registry.get("sha256:" + "a" * 64)
