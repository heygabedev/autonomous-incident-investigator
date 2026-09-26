import ast
import json
import time
from pathlib import Path

import pytest
from incident_investigator.evaluation.canonical import content_digest, parse_json
from incident_investigator.security.policy import Broker
from incident_investigator.workflow.graph import build_graph, invoke
from incident_investigator.workflow.replay import prepare

from .test_graph import execute, setup
from .test_replay import GOLDEN, MEMBERS, incident


def test_public_development_labels_are_used_only_by_test_scorer() -> None:
    for index, member in enumerate(MEMBERS):
        state, context, policy = setup(index)
        result = execute(state, context, policy)
        assert result.report is not None
        labels = json.loads((GOLDEN / "labels" / f"{member['case_id']}.json").read_text())
        supported = [item for item in result.report.hypotheses if item.verdict == "supported"]
        assert {item.cause for item in supported} == set(labels["acceptable_causes"])
        if supported:
            cited = {item for hypothesis in supported for item in hypothesis.evidence_ids}
            sources = {
                item.source_id for item in result.incident.observations if item.evidence.id in cited
            }
            assert set(labels["required_evidence_ids"]).issubset(sources)
        else:
            assert result.report.status == "unresolved"


def test_ordering_case_names_and_irrelevant_injection_do_not_change_cause() -> None:
    original, context, policy = setup()
    baseline = execute(original, context, policy)
    value = incident().model_copy(
        update={"case_id": "not-a-golden-id", "evidence": tuple(reversed(incident().evidence))}
    )
    ready = prepare(value)
    shuffled = original.model_copy(
        update={
            "incident": ready,
            "input_digest": content_digest(parse_json(ready.model_dump_json())),
        }
    )
    assert execute(shuffled, context, policy).hypotheses == baseline.hypotheses
    poisoned = execute(*setup(5))
    assert poisoned.hypotheses == baseline.hypotheses
    assert "Ignore all" not in poisoned.model_dump_json()


def test_missing_required_signal_is_a_counterfactual_not_a_positive() -> None:
    state, context, policy = setup()
    ready = state.incident.model_copy(
        update={
            "observations": tuple(
                item for item in state.incident.observations if item.signal != "env_removed"
            )
        }
    )
    result = execute(
        state.model_copy(
            update={
                "incident": ready,
                "input_digest": content_digest(parse_json(ready.model_dump_json())),
            }
        ),
        context,
        policy,
    )
    assert result.report is not None and result.report.status == "unresolved"
    assert not result.recommendations


def test_future_evidence_and_completed_state_forgery_are_rejected() -> None:
    state, context, policy = setup()
    graph = build_graph(
        state.pin, context, policy, Broker(lambda: policy, lambda *args: None, lambda: 0)
    )
    for update in ({"visible_ids": ("invented",)}, {"next_stage": "done"}):
        with pytest.raises(ValueError):
            invoke(graph, state.model_copy(update=update))


def test_ambient_tracing_is_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LANGSMITH_TRACING", "true")
    monkeypatch.setenv("LANGCHAIN_TRACING_V2", "true")
    # This test also runs under CI's socket prohibition.
    assert execute(*setup()).report is not None


def test_revocation_after_report_computation_blocks_delivery() -> None:
    from incident_investigator.security.policy import OperationDenied

    state, context, policy = setup()
    current = [policy]

    def checkpoint(result: object) -> None:
        if getattr(result, "report", None) is not None:
            current[0] = policy.model_copy(update={"safe_mode": True})

    graph = build_graph(
        state.pin,
        context,
        policy,
        Broker(lambda: current[0], lambda *args: None, lambda: 0),
        checkpoint,
    )
    with pytest.raises(OperationDenied, match="contained"):
        invoke(graph, state)


def test_fixture_replay_latency_budget() -> None:
    durations = []
    for index in range(6):
        started = time.perf_counter()
        execute(*setup(index))
        durations.append(time.perf_counter() - started)
    assert max(durations) < 10


def test_runtime_does_not_import_gold_loaders_or_unsafe_serializers() -> None:
    root = Path(__file__).resolve().parents[2] / "src/incident_investigator/workflow"
    for path in root.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert node.module not in {"pickle", "yaml"}
                assert not {alias.name for alias in node.names} & {
                    "load_expected",
                    "ExpectedAnswer",
                    "GoldLabels",
                    "JsonPlusSerializer",
                }
            if isinstance(node, ast.Import):
                assert not {alias.name for alias in node.names} & {"pickle", "yaml"}
