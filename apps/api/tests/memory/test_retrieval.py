import pytest
from incident_investigator.memory.contracts import digest
from incident_investigator.memory.retrieval import build_index, hypotheses, search
from incident_investigator.memory.store import MemoryError

from .samples import EMBED, case, case_vectors, query, query_vectors, shift, store


def setup() -> tuple:
    previous = case()
    repository = store(previous)
    generation = build_index(
        "generation-1", repository, EMBED, {previous.id: case_vectors(previous)}
    )
    return previous, repository, generation


def test_retrieval_is_deterministic_with_concrete_generation_and_query_binding() -> None:
    previous, repository, generation = setup()
    current = query()
    before = hypotheses(current)
    matches = search(
        current,
        query_vectors(),
        generation,
        digest(generation),
        repository,
        current.incident.investigation_cutoff,
    )
    assert [item.case_id for item in matches] == [previous.id]
    assert matches[0].query_digest == digest(current)
    assert not matches[0].calibrated
    assert matches == search(
        current,
        query_vectors(),
        generation,
        digest(generation),
        repository,
        current.incident.investigation_cutoff,
    )
    assert before == hypotheses(current)
    assert generation == build_index(
        "generation-1", repository, EMBED, {previous.id: case_vectors(previous)}
    )


@pytest.mark.parametrize(
    "change",
    [
        "lineage",
        "cluster",
        "id",
        "future_resolution",
        "expired",
        "permission",
        "state",
    ],
)
def test_ineligible_cases_are_never_returned(change: str) -> None:
    previous = case()
    current = query()
    if change == "lineage":
        previous = previous.model_copy(update={"lineage_id": current.lineage_id})
    elif change == "cluster":
        previous = previous.model_copy(
            update={"duplicate_cluster_id": current.duplicate_cluster_id}
        )
    elif change == "id":
        current = current.model_copy(
            update={"incident": current.incident.model_copy(update={"case_id": previous.id})}
        )
    elif change == "future_resolution":
        previous = previous.model_copy(
            update={
                "resolved_at": current.incident.window_start,
                "revision_created_at": current.incident.window_start,
            }
        )
    elif change == "expired":
        previous = previous.model_copy(
            update={"valid_until": current.incident.investigation_cutoff}
        )
    elif change == "permission":
        previous = previous.model_copy(
            update={"runtime_memory_approved": False, "evaluation_approved": True}
        )
    else:
        previous = previous.model_copy(
            update={"state": "pending", "runtime_memory_approved": False}
        )
    repository = store(previous)
    generation = build_index(
        "generation-1", repository, EMBED, {previous.id: case_vectors(previous)}
    )
    assert not search(
        current,
        query_vectors(current),
        generation,
        digest(generation),
        repository,
        current.incident.investigation_cutoff,
    )


def test_revocation_after_index_creation_and_stale_case_updates() -> None:
    previous, repository, generation = setup()
    withdrawn = previous.model_copy(
        update={
            "revision": 2,
            "parent_digest": digest(previous),
            "state": "revoked",
            "runtime_memory_approved": False,
        }
    )
    repository.put(withdrawn, digest(previous))
    assert not search(
        query(),
        query_vectors(),
        generation,
        digest(generation),
        repository,
        query().incident.investigation_cutoff,
    )
    previous, repository, generation = setup()
    updated = previous.model_copy(
        update={"revision": 2, "parent_digest": digest(previous), "evaluation_approved": True}
    )
    repository.put(updated, digest(previous))
    with pytest.raises(MemoryError, match="retrieval_failed_closed"):
        search(
            query(),
            query_vectors(),
            generation,
            digest(generation),
            repository,
            query().incident.investigation_cutoff,
        )


@pytest.mark.parametrize(
    "change", ["fingerprint", "document", "vector", "dimension", "future_query"]
)
def test_integrity_mismatches_fail_closed(change: str) -> None:
    _, repository, generation = setup()
    qvectors = query_vectors()
    expected = digest(generation)
    now = query().incident.investigation_cutoff
    if change == "fingerprint":
        expected = "sha256:" + "0" * 64
    elif change == "document":
        document = generation.documents[0].model_copy(update={"evidence_terms": ("poisoned",)})
        generation = generation.model_copy(update={"documents": (document,)})
        expected = digest(generation)
    elif change == "vector":
        qvectors = qvectors.model_copy(
            update={
                "evidence": qvectors.evidence.model_copy(
                    update={"document_digest": "sha256:" + "0" * 64}
                )
            }
        )
    elif change == "dimension":
        generation = generation.model_copy(
            update={"embedding": EMBED.model_copy(update={"dimensions": 512})}
        )
    else:
        now = shift(now, -1)
    with pytest.raises(MemoryError):
        search(query(), qvectors, generation, expected, repository, now)


def test_missing_embeddings_do_not_create_partial_generations() -> None:
    with pytest.raises(MemoryError, match="embedding_coverage_gap"):
        build_index("generation-1", store(case()), EMBED, {})


def test_related_historical_variants_are_deduplicated() -> None:
    a = case("a")
    b = case("b").model_copy(update={"lineage_id": a.lineage_id})
    repository = store(a, b)
    generation = build_index(
        "generation-1", repository, EMBED, {a.id: case_vectors(a), b.id: case_vectors(b)}
    )
    matches = search(
        query(),
        query_vectors(),
        generation,
        digest(generation),
        repository,
        query().incident.investigation_cutoff,
    )
    assert len(matches) == 1 and matches[0].case_id == "a"


def test_uncollected_evidence_cannot_anchor_current_hypotheses_or_embeddings() -> None:
    from incident_investigator.memory.calibration import features
    from incident_investigator.memory.retrieval import query_terms

    current = query()
    incident = current.incident.model_copy(
        update={
            "observations": tuple(
                item.model_copy(update={"available_round": 2}) if item.modality == "log" else item
                for item in current.incident.observations
            )
        }
    )
    current = current.model_copy(update={"incident": incident})
    assert not features(current, case()).cause_supported
    assert not any(term.startswith("log.") for term in query_terms(current)[0])
    collected = current.model_copy(update={"collected_round": 2})
    assert features(collected, case()).cause_supported
    assert any(term.startswith("log.") for term in query_terms(collected)[0])
