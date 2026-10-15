import json
from datetime import datetime, timedelta
from pathlib import Path

from incident_investigator.evaluation.canonical import content_digest
from incident_investigator.evaluation.golden import load_input
from incident_investigator.memory.contracts import (
    DocumentVector,
    MemoryCase,
    Query,
    Runbook,
    VectorPair,
    digest,
)
from incident_investigator.memory.retrieval import document_digest, evidence_terms, query_terms
from incident_investigator.memory.store import FixtureCaseStore
from incident_investigator.providers.bedrock import EmbeddingConfig
from incident_investigator.workflow.contracts import ReplayInput
from incident_investigator.workflow.reasoning import PLANS
from incident_investigator.workflow.replay import prepare

ROOT = Path(__file__).resolve().parents[4] / "fixtures/evaluation/golden/v1"
EMBED = EmbeddingConfig(region="eu-central-1")
CAUSE = "missing_required_environment_variable"


def incident() -> ReplayInput:
    entry = json.loads((ROOT / "manifest.json").read_text())["members"][0]
    return prepare(load_input(ROOT / "inputs", entry["case_id"], entry["input_digest"]))


def shift(value: str, days: int) -> str:
    return (datetime.fromisoformat(value) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def query() -> Query:
    return Query(
        incident=incident(), lineage_id="current-lineage", duplicate_cluster_id="current-cluster"
    )


def case(name: str = "past-1") -> MemoryCase:
    old = incident().model_dump(mode="json")
    old["case_id"] = name
    for key in ("window_start", "window_end", "investigation_cutoff"):
        old[key] = shift(old[key], -30)
    for item in old["observations"]:
        for key in ("occurred_at", "observed_at"):
            item[key] = shift(item[key], -30)
    resolved = shift(old["investigation_cutoff"], 1)
    expiry = shift(resolved, 365)
    book = Runbook(
        id="restore-setting",
        revision=1,
        cause=CAUSE,
        state="verified",
        reviewed_at=resolved,
        expires_at=expiry,
        template_digest=content_digest(list(PLANS[CAUSE])),
    )
    return MemoryCase(
        id=name,
        revision=1,
        lineage_id="lineage-" + name,
        duplicate_cluster_id="cluster-" + name,
        incident=ReplayInput.model_validate_json(json.dumps(old)),
        resolved_at=resolved,
        revision_created_at=resolved,
        valid_until=expiry,
        state="verified",
        verified_cause=CAUSE,
        runtime_memory_approved=True,
        evaluation_approved=False,
        runbook=book,
    )


def vectors(terms: tuple[str, ...], causes: tuple[str, ...], coordinate: int = 0) -> VectorPair:
    values = tuple(1.0 if index == coordinate else 0.0 for index in range(256))
    return VectorPair(
        evidence=DocumentVector(
            document_digest=document_digest(terms, "observed_evidence"),
            embedding_fingerprint=digest(EMBED),
            values=values,
        ),
        cause=DocumentVector(
            document_digest=document_digest(causes, "cause"),
            embedding_fingerprint=digest(EMBED),
            values=values,
        ),
    )


def case_vectors(value: MemoryCase) -> VectorPair:
    return vectors(evidence_terms(value.incident), (value.verified_cause,))


def query_vectors(value: Query | None = None) -> VectorPair:
    return vectors(*query_terms(value or query()))


def store(*cases: MemoryCase) -> FixtureCaseStore:
    result = FixtureCaseStore()
    for value in cases:
        result.put_runbook(value.runbook)
        result.put(value)
    return result
