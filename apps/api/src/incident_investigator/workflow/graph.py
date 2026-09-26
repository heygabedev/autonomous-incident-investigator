"""Typed LangGraph with sanitized state and serial, deterministic recovery boundaries."""

import operator
from collections.abc import Callable
from typing import Annotated, Any, Literal, Protocol, TypedDict, cast

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langsmith import tracing_context

from incident_investigator.evaluation.canonical import canonical_bytes, content_digest, parse_json
from incident_investigator.security.evidence import ReportClaim, evidence_bytes, publication_bytes
from incident_investigator.security.policy import (
    ActionRequest,
    Broker,
    SecurityContext,
    SecurityPolicy,
)
from incident_investigator.workflow.contracts import (
    CoverageGap,
    InvestigationReport,
    Modality,
    RunPin,
    RunState,
    Stage,
)
from incident_investigator.workflow.reasoning import (
    TITLES,
    hypothesize,
    observations,
    recommend,
    verify,
)

MODALITIES: tuple[Modality, ...] = ("log", "metric", "trace", "change")


class GraphState(TypedDict):
    run: dict[str, Any]


class CollectorState(TypedDict):
    run: dict[str, Any]
    visible: Annotated[list[str], operator.add]


class WorkflowNode(Protocol):
    def __call__(self, state: GraphState) -> GraphState: ...


class CollectorNode(Protocol):
    def __call__(self, state: CollectorState) -> dict[str, list[str]]: ...


def decode(value: dict[str, Any]) -> RunState:
    return RunState.model_validate_json(canonical_bytes(value))


def collect_graph() -> CompiledStateGraph[CollectorState, None, CollectorState, CollectorState]:
    builder = StateGraph(CollectorState)

    def specialist(modality: Modality) -> CollectorNode:
        def collect(state: CollectorState) -> dict[str, list[str]]:
            run = decode(state["run"])
            return {
                "visible": [
                    item.source_id
                    for item in run.incident.observations
                    if item.modality == modality and item.available_round <= run.evidence_rounds
                ]
            }

        return collect

    for modality in MODALITIES:
        builder.add_node(modality, specialist(modality))
        builder.add_edge(START, modality)
        builder.add_edge(modality, END)
    return builder.compile()


def validate_state(state: RunState, pin: RunPin) -> None:
    if state.pin != pin:
        raise ValueError("release_or_candidate_mismatch")
    if content_digest(parse_json(state.incident.model_dump_json())) != state.input_digest:
        raise ValueError("input_digest_mismatch")
    known = {item.evidence.id for item in observations(state)}
    if any(not set(item.evidence_ids).issubset(known) for item in state.hypotheses):
        raise ValueError("fabricated_citation")
    if state.evidence_rounds > state.round_limit:
        raise ValueError("evidence_round_limit")


def build_graph(
    pin: RunPin,
    context: SecurityContext,
    policy: SecurityPolicy,
    broker: Broker,
    checkpoint: Callable[[RunState], None] | None = None,
    stop_after: Stage | None = None,
) -> CompiledStateGraph[GraphState, None, GraphState, GraphState]:
    if context.candidate_id != pin.candidate_id or context.policy_id != policy.id:
        raise ValueError("runtime_identity_mismatch")
    if pin.policy_digest != content_digest(parse_json(policy.model_dump_json())):
        raise ValueError("pinned_policy_mismatch")
    collectors = collect_graph()

    def node(stage: Stage) -> WorkflowNode:
        def execute(carrier: GraphState) -> GraphState:
            state = decode(carrier["run"])
            validate_state(state, pin)
            if state.next_stage != stage:
                raise ValueError("unexpected_graph_stage")
            incident = state.incident
            request = ActionRequest(
                operation="report.publish" if stage == "report" else "fixture.read",
                account_id=incident.account_id,
                region=incident.region,
                resource=incident.resource,
                template="offline-investigation-v1",
                result_limit=max(1, len(incident.observations)),
                cost_microdollars=0,
            )

            def advance(_: ActionRequest) -> RunState:
                changes: dict[str, Any] = {}
                next_stage: Stage
                if stage == "scope":
                    next_stage = "collect"
                elif stage == "collect":
                    result = collectors.invoke({"run": carrier["run"], "visible": []})
                    changes = {
                        "visible_ids": sorted(set(result["visible"])),
                        "collected": list(MODALITIES),
                    }
                    next_stage = "correlate"
                elif stage == "correlate":
                    changes = {
                        "timeline": [
                            item.evidence.id
                            for item in sorted(
                                observations(state),
                                key=lambda item: (item.occurred_at, item.evidence.id),
                            )
                        ]
                    }
                    next_stage = "hypothesize"
                elif stage == "hypothesize":
                    changes = {
                        "hypotheses": [item.model_dump(mode="json") for item in hypothesize(state)]
                    }
                    next_stage = "verify"
                elif stage == "verify":
                    checked = verify(state)
                    changes = {"hypotheses": [item.model_dump(mode="json") for item in checked]}
                    supported = sum(item.verdict == "supported" for item in checked)
                    pending = any(
                        state.evidence_rounds < item.available_round <= state.round_limit
                        for item in incident.observations
                    )
                    next_stage = "history" if supported == 1 and not pending else "request"
                elif stage == "request":
                    # Captured data is finite. Do not retry an exhausted snapshot.
                    more = any(
                        state.evidence_rounds < item.available_round <= state.round_limit
                        for item in incident.observations
                    )
                    if more and state.evidence_rounds < state.round_limit:
                        changes = {"evidence_rounds": state.evidence_rounds + 1}
                        next_stage = "collect"
                    else:
                        next_stage = "history"
                elif stage == "history":
                    changes = {"history_status": "disabled"}
                    next_stage = "plan"
                elif stage == "plan":
                    changes = {
                        "recommendations": [
                            item.model_dump(mode="json") for item in recommend(state)
                        ]
                    }
                    next_stage = "report"
                elif stage == "report":
                    report = make_report(state)
                    changes = {"report": report.model_dump(mode="json")}
                    next_stage = "done"
                else:
                    raise ValueError("invalid_stage")
                result_state = decode(
                    {
                        **state.model_dump(mode="json"),
                        **changes,
                        "next_stage": next_stage,
                        "completed": [*state.completed, stage],
                    }
                )
                validate_state(result_state, pin)
                if checkpoint is not None:
                    checkpoint(result_state)
                return result_state

            result = broker.dispatch(context, request, policy, advance)
            return {"run": result.model_dump(mode="json")}

        def named(state: GraphState) -> GraphState:
            return execute(state)

        return named

    def route(carrier: GraphState) -> str:
        state = decode(carrier["run"])
        if state.next_stage == "done" or (
            stop_after is not None and state.completed and state.completed[-1] == stop_after
        ):
            return END
        return state.next_stage

    builder = StateGraph(GraphState)
    stages: tuple[Stage, ...] = (
        "scope",
        "collect",
        "correlate",
        "hypothesize",
        "verify",
        "request",
        "history",
        "plan",
        "report",
    )
    for stage in stages:
        builder.add_node(stage, node(stage))
        builder.add_conditional_edges(stage, route)
    builder.add_conditional_edges(START, route)
    return builder.compile()


def make_report(state: RunState) -> InvestigationReport:
    if state.history_status != "disabled":
        raise ValueError("historical_gate_not_checked")
    checked = verify(state)
    if checked != state.hypotheses or recommend(state) != state.recommendations:
        raise ValueError("unverified_report")
    records = tuple(item.evidence for item in observations(state))
    incident = state.incident
    evidence_bytes(records, incident.account_id, incident.region, (incident.resource,))
    claims = tuple(
        ReportClaim(text=TITLES[item.cause], evidence_ids=item.evidence_ids)
        for item in checked
        if item.verdict == "supported"
    )
    if claims:
        publication_bytes(
            claims, records, incident.account_id, incident.region, (incident.resource,)
        )
    gaps = (
        *incident.gaps,
        *(
            CoverageGap(source_id=item.source_id, modality=item.modality, reason="unavailable")
            for item in incident.observations
            if item.source_id not in state.visible_ids
        ),
    )
    status: Literal["resolved", "degraded", "unresolved"] = (
        "unresolved" if len(claims) != 1 else ("degraded" if gaps else "resolved")
    )
    return InvestigationReport(
        attempt_id=state.attempt_id,
        pin=state.pin,
        status=status,
        hypotheses=checked,
        recommendations=state.recommendations,
        gaps=gaps,
        evidence_ids=tuple(sorted(item.id for item in records)),
    )


def invoke(
    graph: CompiledStateGraph[GraphState, None, GraphState, GraphState], state: RunState
) -> RunState:
    # Prevent ambient LangSmith settings from exporting investigation state.
    with tracing_context(enabled=False):
        output = graph.invoke(
            {"run": state.model_dump(mode="json")},
            config={"recursion_limit": 32, "max_concurrency": 4, "callbacks": []},
        )
    return decode(cast(dict[str, Any], output["run"]))
