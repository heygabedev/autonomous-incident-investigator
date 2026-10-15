"""Bounded offline hybrid retrieval. A rank is never admission authority."""

import math
from collections import Counter

from pydantic import TypeAdapter

from incident_investigator.evaluation.canonical import content_digest
from incident_investigator.evaluation.models import Timestamp
from incident_investigator.memory.contracts import (
    IndexDocument,
    IndexGeneration,
    Match,
    MemoryCase,
    Query,
    VectorPair,
    digest,
)
from incident_investigator.memory.store import FixtureCaseStore, MemoryError
from incident_investigator.providers.bedrock import EmbeddingConfig
from incident_investigator.workflow.contracts import Hypothesis, Observation, ReplayInput
from incident_investigator.workflow.reasoning import hypothesize_observations, verify_hypotheses


def current_observations(query: Query) -> tuple[Observation, ...]:
    return tuple(
        item
        for item in query.incident.observations
        if item.available_round <= query.collected_round
    )


def hypotheses(query: Query) -> tuple[Hypothesis, ...]:
    # Deterministic current-only hypotheses precede all historical retrieval.
    return verify_hypotheses(
        hypothesize_observations(query.incident.workload, current_observations(query)),
        current_observations(query),
    )


def evidence_terms(incident: ReplayInput) -> tuple[str, ...]:
    return tuple(
        sorted(
            [
                incident.workload,
                *(f"{item.modality}.{item.signal}" for item in incident.observations),
            ]
        )
    )


def document_digest(terms: tuple[str, ...], kind: str) -> str:
    return content_digest({"template": "history-document-v1", "kind": kind, "terms": list(terms)})


def query_terms(query: Query) -> tuple[tuple[str, ...], tuple[str, ...]]:
    query = Query.model_validate_json(query.model_dump_json())
    visible = query.incident.model_copy(update={"observations": current_observations(query)})
    return evidence_terms(visible), tuple(sorted(item.cause for item in hypotheses(query)))


def validate_vectors(
    vectors: VectorPair,
    evidence: tuple[str, ...],
    causes: tuple[str, ...],
    embedding: EmbeddingConfig,
) -> VectorPair:
    vectors = VectorPair.model_validate_json(vectors.model_dump_json())
    for vector, terms, kind in (
        (vectors.evidence, evidence, "observed_evidence"),
        (vectors.cause, causes, "cause"),
    ):
        if vector.document_digest != document_digest(terms, kind):
            raise MemoryError("embedding_document_mismatch")
        if (
            vector.embedding_fingerprint != digest(embedding)
            or len(vector.values) != embedding.dimensions
        ):
            raise MemoryError("embedding_configuration_mismatch")
    return vectors


def build_index(
    name: str, store: FixtureCaseStore, embedding: EmbeddingConfig, vectors: dict[str, VectorPair]
) -> IndexGeneration:
    documents: list[IndexDocument] = []
    for case in store.snapshot():
        if case.state != "verified" or not case.runtime_memory_approved:
            continue
        if case.id not in vectors:
            raise MemoryError("embedding_coverage_gap")
        terms, causes = evidence_terms(case.incident), (case.verified_cause,)
        documents.append(
            IndexDocument(
                case_id=case.id,
                case_digest=digest(case),
                evidence_terms=terms,
                cause_terms=causes,
                vectors=validate_vectors(vectors[case.id], terms, causes, embedding),
            )
        )
    return IndexGeneration(id=name, embedding=embedding, documents=tuple(documents))


def eligible(case: MemoryCase, query: Query, now: str) -> bool:
    return (
        case.state == "verified"
        and case.runtime_memory_approved
        and case.lineage_id != query.lineage_id
        and case.duplicate_cluster_id != query.duplicate_cluster_id
        and case.id != query.incident.case_id
        and case.resolved_at < query.incident.window_start
        and case.revision_created_at < query.incident.window_start
        and case.resolved_at <= now < case.valid_until
        and case.incident.account_id == query.incident.account_id
        and case.incident.region == query.incident.region
        and case.incident.workload == query.incident.workload
    )


def _bm25(query: tuple[str, ...], documents: list[IndexDocument]) -> list[float]:
    counts = [Counter(item.evidence_terms) for item in documents]
    average = sum(sum(item.values()) for item in counts) / max(len(counts), 1)
    scores = [0.0] * len(counts)
    for term in sorted(set(query)):
        frequency = sum(term in item for item in counts)
        weight = math.log(1 + (len(counts) - frequency + 0.5) / (frequency + 0.5))
        for index, counter in enumerate(counts):
            tf = counter[term]
            denominator = tf + 1.2 * (0.25 + 0.75 * sum(counter.values()) / max(average, 1))
            scores[index] += weight * (tf * 2.2 / denominator)
    return scores


def search(
    query: Query,
    vectors: VectorPair,
    generation: IndexGeneration,
    expected_fingerprint: str,
    store: FixtureCaseStore,
    now: str,
) -> tuple[Match, ...]:
    try:
        now = TypeAdapter(Timestamp).validate_python(now)
        query = Query.model_validate_json(query.model_dump_json())
        if now < query.incident.investigation_cutoff:
            raise MemoryError("query_from_future")
        generation = IndexGeneration.model_validate_json(generation.model_dump_json())
        fingerprint = digest(generation)
        if fingerprint != expected_fingerprint:
            raise MemoryError("index_fingerprint_mismatch")
        terms, causes = query_terms(query)
        vectors = validate_vectors(vectors, terms, causes, generation.embedding)
        documents: list[IndexDocument] = []
        cases: dict[str, MemoryCase] = {}
        for document in generation.documents:
            case = store.read(document.case_id)
            # Withdrawals are excluded immediately; other unexpected drift fails closed.
            if not eligible(case, query, now):
                continue
            if digest(case) != document.case_digest:
                raise MemoryError("stale_index_case")
            if document.evidence_terms != evidence_terms(case.incident) or document.cause_terms != (
                case.verified_cause,
            ):
                raise MemoryError("index_document_mismatch")
            validate_vectors(
                document.vectors,
                document.evidence_terms,
                document.cause_terms,
                generation.embedding,
            )
            cases[case.id] = case
            documents.append(document)
        if not documents:
            return ()
        channels = [_bm25(terms, documents)]
        for field in ("evidence", "cause"):
            if field == "cause" and not causes:
                continue
            query_vector = getattr(vectors, field).values
            channels.append(
                [
                    math.fsum(
                        a * b
                        for a, b in zip(
                            query_vector, getattr(doc.vectors, field).values, strict=True
                        )
                    )
                    for doc in documents
                ]
            )
        channels.append(
            [
                float(cases[doc.case_id].incident.resource == query.incident.resource)
                + float(cases[doc.case_id].verified_cause in causes)
                for doc in documents
            ]
        )
        scores = [0.0] * len(documents)
        for channel in channels:
            order = sorted(range(len(documents)), key=lambda i: (-channel[i], documents[i].case_id))
            for rank, index in enumerate(order, start=1):
                if channel[index] > 0:
                    scores[index] += 1 / (60 + rank)
        order = sorted(range(len(documents)), key=lambda i: (-scores[i], documents[i].case_id))
        matches: list[Match] = []
        seen: set[str] = set()
        for index in order:
            document = documents[index]
            case = cases[document.case_id]
            keys = {"lineage:" + case.lineage_id, "cluster:" + case.duplicate_cluster_id}
            if seen.intersection(keys) or scores[index] == 0:
                continue
            seen.update(keys)
            matches.append(
                Match(
                    case_id=case.id,
                    case_digest=document.case_digest,
                    query_digest=digest(query),
                    index_fingerprint=fingerprint,
                    rank=len(matches) + 1,
                    fusion_score=scores[index],
                )
            )
            if len(matches) == 20:
                break
        return tuple(matches)
    except (ValueError, TypeError, KeyError, AttributeError):
        raise MemoryError("retrieval_failed_closed") from None
