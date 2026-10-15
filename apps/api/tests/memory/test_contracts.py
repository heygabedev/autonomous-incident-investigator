import json
from pathlib import Path
from typing import Any

import pytest
from incident_investigator.memory.contracts import MemoryCase, Runbook, VectorPair, digest
from incident_investigator.memory.retrieval import build_index
from incident_investigator.memory.store import MemoryError
from incident_investigator.security.policy import OPERATIONS

from .samples import EMBED, case, case_vectors, query, store


@pytest.mark.parametrize(
    "change",
    [
        {"id": "wrong"},
        {"revision_created_at": "2000-01-01T00:00:00Z"},
        {"resolved_at": "2000-01-01T00:00:00Z"},
        {"verified_cause": "target_group_port_mismatch"},
        {"parent_digest": "sha256:" + "0" * 64},
        {"revision": 2},
        {"lineage_id": "AKIA" + "Z" * 16},
        {"source": "sanitized_real"},
    ],
)
def test_invalid_case_metadata_is_not_admitted(change: dict[str, Any]) -> None:
    assert MemoryCase.model_validate_json(case().model_dump_json()) == case()
    with pytest.raises(ValueError):
        MemoryCase.model_validate(case().model_dump() | change)


@pytest.mark.parametrize(
    "change",
    [
        {"template_digest": "sha256:" + "0" * 64},
        {"expires_at": "2000-01-01T00:00:00Z"},
        {"id": "AKIA" + "Z" * 16},
        {"command": "delete"},
    ],
)
def test_runbook_template_and_currency_are_validated(change: dict[str, Any]) -> None:
    book = case().runbook
    assert Runbook.model_validate_json(book.model_dump_json()) == book
    with pytest.raises(ValueError):
        Runbook.model_validate(book.model_dump() | change)


@pytest.mark.parametrize(
    "values",
    [
        tuple([0.0] * 256),
        tuple([float("nan")] + [0.0] * 255),
        tuple([float("inf")] + [0.0] * 255),
        tuple([2.0] + [0.0] * 255),
    ],
)
def test_invalid_vectors_fail_before_index_creation(values: tuple[float, ...]) -> None:
    valid = case_vectors(case())
    assert VectorPair.model_validate_json(valid.model_dump_json()) == valid
    invalid = valid.model_copy(
        update={"evidence": valid.evidence.model_copy(update={"values": values})}
    )
    with pytest.raises(ValueError):
        build_index("index", store(case()), EMBED, {case().id: invalid})


def test_case_integrity_and_missing_records_fail_closed() -> None:
    original = case()
    repository = store(original)
    with pytest.raises(MemoryError, match="case_unavailable"):
        repository.read("missing")
    # Simulated corruption of the authoritative fixture store, not an index write.
    repository._revisions[digest(original)] = original.model_copy(
        update={"evaluation_approved": True}
    )
    with pytest.raises(MemoryError, match="case_integrity"):
        repository.read(original.id)


def test_future_revision_is_excluded_even_when_resolution_precedes_query() -> None:
    from incident_investigator.memory.retrieval import search

    from .samples import query_vectors

    current, previous = query(), case()
    previous = previous.model_copy(update={"revision_created_at": current.incident.window_start})
    repository = store(previous)
    generation = build_index("index", repository, EMBED, {previous.id: case_vectors(previous)})
    assert not search(
        current,
        query_vectors(),
        generation,
        digest(generation),
        repository,
        current.incident.investigation_cutoff,
    )


def test_control_inventory_matches_disabled_live_operations() -> None:
    root = Path(__file__).resolve().parents[4]
    inventory = json.loads((root / "security/bedrock-memory.json").read_text())
    assert not inventory["live_enabled"] and not inventory["historical_publication_enabled"]
    for contract in inventory["provider_contracts"]:
        assert OPERATIONS[contract["operation"]] == ("model", True)
        assert contract["iam_action"] == "bedrock:InvokeModel"
