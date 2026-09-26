"""Synthetic metadata only: these records are not benchmark or release evidence."""

from __future__ import annotations

import json
from typing import Any

from incident_investigator.evaluation.artifacts import parse_artifact
from incident_investigator.evaluation.models import Artifact

DIGEST = "sha256:" + "a" * 64
TIME = "2026-09-25T12:00:00Z"


def component(name: str = "fixture-component") -> dict[str, str]:
    return {"name": name, "version": "1.0.0", "digest": DIGEST}


def ref(kind: str, identifier: str = "fixture") -> dict[str, str]:
    return {"kind": kind, "id": identifier, "version": "1.0.0", "digest": DIGEST}


def payload(kind: str = "candidate_bundle", identifier: str = "fixture") -> dict[str, Any]:
    common: dict[str, Any] = {
        "kind": kind,
        "id": identifier,
        "version": "1.0.0",
        "created_at": TIME,
    }
    specifics: dict[str, dict[str, Any]] = {
        "case_revision": {
            "candidate_input": {
                "case_id": identifier,
                "input_digest": DIGEST,
                "investigation_cutoff": TIME,
            },
            "gold_labels": {
                "case_id": identifier,
                "labels_digest": DIGEST,
                "labeling_policy": component(),
            },
            "source": "synthetic",
            "provenance_digest": DIGEST,
            "lineage_id": identifier,
            "duplicate_cluster_id": identifier,
            "lifecycle": "verified",
            "data_stage": "frozen",
            "permitted_uses": [
                "development",
                "calibration",
                "sealed_benchmark",
                "shadow",
                "regression",
                "public_release",
            ],
        },
        "dataset_snapshot": {
            "members": [{"case": ref("case_revision"), "split": "dev"}],
            "memory_snapshot_digest": DIGEST,
            "governance_digest": DIGEST,
            "sanitizer": component(),
            "labeling_policy": component(),
            "split_policy": component(),
        },
        "candidate_bundle": {
            "code_sha": "a" * 40,
            "source_artifact_digest": DIGEST,
            "dependency_locks": [component("uv-lock")],
            "prompts": [component("hypotheses")],
            "graph": component(),
            "state_schema": component(),
            "report_schema": component(),
            "authorization_policy": component(),
            "admission_policy": component(),
            "redaction": component(),
            "model": {
                "provider": "fixture",
                "model_id": "synthetic-replay",
                "region": "eu-central-1",
                "adapter": component(),
                "settings_digest": DIGEST,
                "inference_destinations": ["eu-central-1"],
            },
            "retrieval": {
                "memory_snapshot_digest": DIGEST,
                "index_generation": "fixture-index-1",
                "embedding": {
                    "model_id": "synthetic-embedding",
                    "dimensions": 8,
                    "normalization": "l2",
                    "document_template_digest": DIGEST,
                },
                "fusion": component(),
                "reranker": component(),
                "feature_schema": component(),
            },
            "calibration": None,
            "historical_actions_enabled": False,
            "cause_threshold_ppm": 900_000,
            "applicability_threshold_ppm": 900_000,
            "budgets": {
                "model_calls": 8,
                "input_tokens": 80_000,
                "output_tokens": 12_000,
                "evidence_rounds": 2,
                "embedding_calls": 2,
                "embedding_input_tokens": 1000,
                "estimated_cost_microdollars": 500_000,
                "rate_card": component(),
            },
        },
        "eval_suite": {
            "name": "pr-smoke",
            "datasets": [ref("dataset_snapshot")],
            "harness": component(),
            "repetitions": 1,
            "gates": [
                {
                    "name": "accuracy",
                    "scorer": component(),
                    "direction": "higher",
                    "threshold_decimal": "0.85",
                    "non_inferiority_margin_decimal": "0.02",
                    "denominator": "all-incidents",
                    "independent_unit": "lineage_cluster",
                    "minimum_independent_samples": 100,
                    "slices": [{"name": "all", "count": 100}],
                    "missing_output_policy": "fail",
                    "statistical_procedure": component(),
                }
            ],
            "max_sealed_submissions": 3,
            "exposure_policy": component(),
            "multiple_testing_policy": component(),
        },
        "calibration_artifact": {
            "retrieval_fingerprint": DIGEST,
            "feature_schema": component(),
            "training_snapshot": ref("dataset_snapshot"),
            "training_split": "calibration",
            "parameters_digest": DIGEST,
            "validation_results_digest": DIGEST,
            "cause_threshold_ppm": 900_000,
            "applicability_threshold_ppm": 900_000,
        },
        "eval_run": {
            "candidate": ref("candidate_bundle"),
            "dataset": ref("dataset_snapshot"),
            "suite": ref("eval_suite"),
            "environment_digest": DIGEST,
            "memory_snapshot_digest": DIGEST,
            "governance_digest": DIGEST,
            "trajectories_digest": DIGEST,
            "results_digest": DIGEST,
            "status": "insufficient_evidence",
            "repetitions": 1,
            "model_calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "cost_microdollars": 0,
            "latency_ms": 0,
        },
        "promotion_decision": {
            "champion": ref("candidate_bundle", "champion"),
            "challenger": ref("candidate_bundle", "challenger"),
            "qualifying_runs": [ref("eval_run")],
            "comparison_digest": DIGEST,
            "reviewer": "synthetic-reviewer",
            "decision": "insufficient_evidence",
            "rollback_target": ref("release_bundle"),
        },
        "release_bundle": {
            "candidate": ref("candidate_bundle"),
            "evaluation_run": ref("eval_run"),
            "approval": ref("promotion_decision"),
            "application_artifacts": [component(name) for name in ("api", "worker", "ui")],
            "compatibility": [
                {"name": name, "supported_versions": ["1.0.0"]}
                for name in ("api", "sse", "report", "event", "database", "checkpoint")
            ],
            "terraform": component(),
            "infrastructure_prerequisites_digest": DIGEST,
            "previous_known_good": None,
        },
        "invalidation": {
            "target": ref("candidate_bundle"),
            "actor": "synthetic-owner",
            "reason_code": "withdrawn",
            "evidence_digest": DIGEST,
        },
        "exposure": {
            "dataset": ref("dataset_snapshot"),
            "candidate": ref("candidate_bundle"),
            "actor": "synthetic-reviewer",
            "disclosure": "submission",
        },
    }
    return common | specifics[kind]


def artifact(kind: str = "candidate_bundle", identifier: str = "fixture") -> Artifact:
    return parse_artifact(json.dumps(payload(kind, identifier)))
