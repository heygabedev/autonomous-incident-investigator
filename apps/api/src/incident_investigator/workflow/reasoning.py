"""Conservative synthetic baseline. These rules produce no calibrated probabilities."""

from typing import Literal

from incident_investigator.workflow.contracts import (
    Cause,
    Hypothesis,
    Observation,
    Recommendation,
    RunState,
    Signal,
)

REQUIRED: dict[Cause, tuple[Signal, ...]] = {
    "missing_required_environment_variable": ("env_removed", "startup_missing_env"),
    "dynamodb_write_throttling": ("write_capacity_exhausted", "putitem_throttled"),
    "target_group_port_mismatch": ("port_mismatch", "listener_ready", "health_probe_failure"),
    "execution_role_permission_removed": ("getitem_permission_removed", "getitem_denied"),
}
SUPPORT: dict[Cause, tuple[Signal, ...]] = {
    **REQUIRED,
    "missing_required_environment_variable": (
        *REQUIRED["missing_required_environment_variable"],
        "target_health_loss",
    ),
    "dynamodb_write_throttling": (*REQUIRED["dynamodb_write_throttling"], "throughput_exceeded"),
    "execution_role_permission_removed": (
        *REQUIRED["execution_role_permission_removed"],
        "getitem_failure_no_throttle",
    ),
}
TITLES: dict[Cause, str] = {
    "missing_required_environment_variable": (
        "The deployment omitted a required environment setting."
    ),
    "dynamodb_write_throttling": "DynamoDB write throttling contributed to failed requests.",
    "target_group_port_mismatch": "The target group port did not match the application listener.",
    "execution_role_permission_removed": "The execution role lost the required GetItem permission.",
}
PLANS: dict[Cause, tuple[str, str, str, str, str]] = {
    "missing_required_environment_variable": (
        "Have an operator review restoring the required setting or reverting the rollout.",
        "Confirm the intended setting and a compatible known-good task definition.",
        "A replacement rollout can interrupt requests and may be incompatible with current data.",
        "Retain the current definition; stop the rollout and restore the compatible prior "
        "definition if validation fails.",
        "Verify task startup, target health and error rate before completing the rollout.",
    ),
    "dynamodb_write_throttling": (
        "Have an operator review capacity and write distribution before choosing an adjustment.",
        "Confirm quotas, capacity mode, hot partitions and a cost limit.",
        "Capacity increases incur cost and do not necessarily fix a hot partition.",
        "Retain previous capacity settings and restore them "
        "if the approved adjustment fails validation.",
        "Compare throttled writes, request success and latency against the pre-change baseline.",
    ),
    "target_group_port_mismatch": (
        "Have an operator align routing and listener ports in a reviewed rollout.",
        "Confirm the intended listener, health-check port and a known-good routing configuration.",
        "Changing routing can interrupt traffic or direct it to an unintended listener.",
        "Restore the prior compatible routing and task definition if health checks regress.",
        "Verify health probes and representative requests before completing the routing change.",
    ),
    "execution_role_permission_removed": (
        "Have an operator review restoring only the required resource-scoped GetItem permission.",
        "Confirm the intended table and role policy; do not grant wildcard permissions.",
        "An overly broad policy can expose unrelated data.",
        "Retain and restore the reviewed previous policy version "
        "if the change grants unintended access.",
        "Verify GetItem on the intended table and denial against an out-of-scope resource.",
    ),
}


def observations(state: RunState) -> tuple[Observation, ...]:
    return tuple(
        item for item in state.incident.observations if item.source_id in state.visible_ids
    )


def hypothesize(state: RunState) -> tuple[Hypothesis, ...]:
    observed = observations(state)
    results: list[Hypothesis] = []
    for cause, signals in SUPPORT.items():
        ecs = cause in ("missing_required_environment_variable", "target_group_port_mismatch")
        if ecs != (state.incident.workload == "ecs_fargate"):
            continue
        support = [item for item in observed if item.signal in signals]
        if support:
            if cause == "missing_required_environment_variable":
                support.extend(item for item in observed if item.signal == "startup_healthy")
            results.append(
                Hypothesis(
                    cause=cause, evidence_ids=tuple(sorted(item.evidence.id for item in support))
                )
            )
    return tuple(sorted(results, key=lambda item: (-len(item.evidence_ids), item.cause)))


def verify(state: RunState) -> tuple[Hypothesis, ...]:
    observed = observations(state)
    results: list[Hypothesis] = []
    for hypothesis in state.hypotheses:
        support = [item for item in observed if item.evidence.id in hypothesis.evidence_ids]
        complete = set(REQUIRED[hypothesis.cause]).issubset(item.signal for item in support)
        core = [item for item in support if item.signal in REQUIRED[hypothesis.cause]]
        independent = any(
            a.modality != b.modality and a.provenance_group != b.provenance_group
            for a in core
            for b in core
        )
        cohorts = {item.cohort for item in support if item.cohort is not None}
        changes = [item.occurred_at for item in support if item.modality == "change"]
        symptoms = [item.occurred_at for item in support if item.modality != "change"]
        ordered = not changes or bool(symptoms and max(changes) <= min(symptoms))
        contradiction = hypothesis.cause == "missing_required_environment_variable" and any(
            item.signal == "startup_healthy" and (item.cohort is None or item.cohort in cohorts)
            for item in observed
        )
        verdict: Literal["supported", "insufficient", "contradicted"] = (
            "contradicted"
            if contradiction
            else (
                "supported"
                if complete and independent and len(cohorts) <= 1 and ordered
                else "insufficient"
            )
        )
        results.append(
            Hypothesis(
                cause=hypothesis.cause, evidence_ids=hypothesis.evidence_ids, verdict=verdict
            )
        )
    return tuple(results)


def recommend(state: RunState) -> tuple[Recommendation, ...]:
    supported = [item for item in state.hypotheses if item.verdict == "supported"]
    if len(supported) != 1:
        return ()
    hypothesis = supported[0]
    instruction, prerequisites, risk, rollback, validation = PLANS[hypothesis.cause]
    return (
        Recommendation(
            cause=hypothesis.cause,
            instruction=instruction,
            prerequisites=prerequisites,
            risk=risk,
            rollback=rollback,
            validation=validation,
            evidence_ids=hypothesis.evidence_ids,
        ),
    )
