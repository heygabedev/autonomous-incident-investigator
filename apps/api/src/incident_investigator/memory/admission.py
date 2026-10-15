"""Audited synthetic admission previews, deliberately disconnected from publication."""

from typing import Annotated, Literal

from pydantic import Field

from incident_investigator.evaluation.models import Contract, Digest, Identifier, Text
from incident_investigator.memory.calibration import (
    AdmissionPin,
    Calibration,
    LabeledPair,
    PrecisionResult,
    Probabilities,
    features,
    precision_check,
    predict,
)
from incident_investigator.memory.contracts import IndexGeneration, Query, VectorPair, digest
from incident_investigator.memory.retrieval import eligible, search
from incident_investigator.memory.store import FixtureCaseStore
from incident_investigator.security.policy import (
    ActionRequest,
    Broker,
    OperationDenied,
    SecurityContext,
    SecurityPolicy,
)
from incident_investigator.workflow.contracts import Cause
from incident_investigator.workflow.reasoning import PLANS
from incident_investigator.workflow.runtime import runtime_digest


class ActionPreview(Contract):
    case_id: Identifier
    case_digest: Digest
    runbook_digest: Digest
    cause: Cause
    instruction: Text
    prerequisites: Text
    risk: Text
    rollback: Text
    validation: Text
    differences: tuple[Literal["resource_changed", "evidence_changed"], ...]
    probabilities: Probabilities
    execution: Literal["operator_only"] = "operator_only"


class AdmissionPreview(Contract):
    source: Literal["synthetic_development"] = "synthetic_development"
    status: Literal["gates_passed", "no_actions", "failed_closed"]
    reason: Identifier
    actions: Annotated[tuple[ActionPreview, ...], Field(max_length=3)] = ()
    precision: PrecisionResult | None = None
    publication_allowed: Literal[False] = False
    promotion_eligible: Literal[False] = False


def _preview(
    query: Query,
    vectors: VectorPair,
    generation: IndexGeneration,
    pin: AdmissionPin,
    calibration: Calibration,
    held_out: tuple[LabeledPair, ...],
    store: FixtureCaseStore,
    now: str,
) -> AdmissionPreview:
    if calibration.pin != pin or pin.reasoning_fingerprint != runtime_digest():
        raise ValueError("calibration_pipeline_mismatch")
    # search() constructs current-only hypotheses before touching historical cases.
    matches = search(query, vectors, generation, pin.index_fingerprint, store, now)
    precision = precision_check(calibration, held_out)
    if precision.status != "passed":
        return AdmissionPreview(status="no_actions", reason="precision_gate", precision=precision)
    actions: list[ActionPreview] = []
    seen: set[str] = set()
    for match in matches:
        # Never reuse the derived index's copy as canonical authority.
        case = store.read(match.case_id)
        book = store.runbook(case.runbook.id)
        if digest(case) != match.case_digest or not eligible(case, query, now):
            raise ValueError("case_changed")
        if (
            digest(book) != digest(case.runbook)
            or book.state != "verified"
            or not book.reviewed_at <= now < book.expires_at
            or book.reviewed_at >= query.incident.window_start
        ):
            continue
        values = features(query, case)
        prediction = predict(calibration, values)
        if (
            not values.cause_supported
            or prediction.same_cause_ppm < pin.cause_threshold_ppm
            or prediction.applicability_ppm < pin.applicability_threshold_ppm
        ):
            continue
        if book.template_digest in seen:
            continue
        seen.add(book.template_digest)
        instruction, prerequisites, risk, rollback, validation = PLANS[case.verified_cause]
        differences: list[Literal["resource_changed", "evidence_changed"]] = []
        if not values.resource_exact:
            differences.append("resource_changed")
        if values.signal_overlap_ppm != 1_000_000:
            differences.append("evidence_changed")
        actions.append(
            ActionPreview(
                case_id=case.id,
                case_digest=digest(case),
                runbook_digest=digest(book),
                cause=case.verified_cause,
                instruction=instruction,
                prerequisites=prerequisites,
                risk=risk,
                rollback=rollback,
                validation=validation,
                differences=tuple(differences),
                probabilities=prediction,
            )
        )
        if len(actions) == 3:
            break
    # Detect changes during evaluation. This is NOT a production publication lease.
    for action in actions:
        current = store.read(action.case_id)
        if (
            digest(current) != action.case_digest
            or digest(store.runbook(current.runbook.id)) != action.runbook_digest
        ):
            raise ValueError("authority_changed")
    return AdmissionPreview(
        status="gates_passed" if actions else "no_actions",
        reason="synthetic_gate_result",
        actions=tuple(actions),
        precision=precision,
    )


def preview(
    query: Query,
    vectors: VectorPair,
    generation: IndexGeneration,
    pin: AdmissionPin,
    calibration: Calibration,
    held_out: tuple[LabeledPair, ...],
    store: FixtureCaseStore,
    now: str,
    broker: Broker,
    context: SecurityContext,
    policy: SecurityPolicy,
) -> AdmissionPreview:
    try:
        query = Query.model_validate_json(query.model_dump_json())
        pin = AdmissionPin.model_validate_json(pin.model_dump_json())
        calibration = Calibration.model_validate_json(calibration.model_dump_json())
        action = ActionRequest(
            operation="history.read",
            account_id=query.incident.account_id,
            region=query.incident.region,
            resource=query.incident.resource,
            template="synthetic-history-v1",
            result_limit=20,
            cost_microdollars=0,
        )
        result = broker.dispatch(
            context,
            action,
            policy,
            lambda _: _preview(query, vectors, generation, pin, calibration, held_out, store, now),
        )
        # Containment/revocation may change during the calculation.
        return broker.dispatch(context, action, policy, lambda _: result)
    except (ValueError, OSError, OperationDenied):
        return AdmissionPreview(
            status="failed_closed", reason="history_unavailable_or_incompatible"
        )
