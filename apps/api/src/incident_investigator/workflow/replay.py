"""Reviewed synthetic telemetry templates; not a general-language RCA classifier.

Only complete matches produce structured signals. Unknown prose and embedded
instructions are omitted before any graph state, tracing or checkpoint exists.
"""

import re

from incident_investigator.evaluation.golden import IncidentInput
from incident_investigator.security.evidence import RawEvidence, sanitize
from incident_investigator.workflow.contracts import (
    CoverageGap,
    Modality,
    Observation,
    ReplayInput,
    Signal,
)

# Full matches and modality constraints prevent suffix/prefix instructions from
# being interpreted as supported telemetry. No labels or case IDs are consulted.
TEMPLATES: tuple[tuple[Modality, Signal, str], ...] = (
    (
        "change",
        "env_removed",
        r"Deployment changed task definition from revision (?P<old>\d+) to (?P<cohort>\d+)\. "
        r"Revision (?P=old) sets CACHE_HOST=cache\.internal; "
        r"revision (?P=cohort) omits CACHE_HOST\.",
    ),
    (
        "log",
        "startup_missing_env",
        r"All revision (?P<cohort>\d+) tasks exit during startup: "
        r"required configuration CACHE_HOST is missing\. Revision \d+ tasks remain healthy\.",
    ),
    (
        "metric",
        "target_health_loss",
        r"Healthy target count decreased from \d+ to \d+ after the revision "
        r"(?P<cohort>\d+) rollout; HTTP 503 responses increased\.",
    ),
    (
        "metric",
        "write_capacity_exhausted",
        r"Synthetic orders table WriteThrottleEvents increased from \d+ to \d+ per minute; "
        r"consumed write capacity reached provisioned write capacity during the same interval\.",
    ),
    (
        "trace",
        "putitem_throttled",
        r"Failed handler requests have DynamoDB PutItem subsegments "
        r"marked throttled after retries\.",
    ),
    (
        "log",
        "throughput_exceeded",
        r"Handler reports ProvisionedThroughputExceededException from PutItem; "
        r"request duration rises from \d+ ms to \d+ ms\.",
    ),
    (
        "change",
        "port_mismatch",
        r"Task definition revision (?P<cohort>\d+) changes the application listener and "
        r"container port from 8080 to 8081\. "
        r"The target group still forwards traffic to port 8080\.",
    ),
    (
        "log",
        "listener_ready",
        r"Revision (?P<cohort>\d+) application startup succeeds "
        r"and reports listening on 0\.0\.0\.0:8081\.",
    ),
    (
        "metric",
        "health_probe_failure",
        r"Health probes to port 8080 fail for every revision (?P<cohort>\d+) target; "
        r"probes to remaining revision \d+ targets succeed\.",
    ),
    (
        "change",
        "getitem_permission_removed",
        r"The handler execution role policy was updated\. The previous policy allowed "
        r"dynamodb:GetItem on the synthetic profiles table; the new policy omits that action\.",
    ),
    (
        "log",
        "getitem_denied",
        r"AccessDeniedException: execution role is not authorized to perform dynamodb:GetItem "
        r"on the profiles table because no identity-based policy allows the action\.",
    ),
    (
        "trace",
        "getitem_failure_no_throttle",
        r"Requests reach the handler and fail at the DynamoDB GetItem subsegment\. "
        r"No throttling is recorded\.",
    ),
    (
        "metric",
        "errors_without_detail",
        r"Handler Errors increased from \d+ to \d+ "
        r"while Invocations remained near \d+ per minute\. "
        r"Duration and concurrency remained within their prior ranges\.",
    ),
    (
        "log",
        "startup_healthy",
        r"Application startup succeeds; all required configuration values are present\.",
    ),
)


def prepare(incident: IncidentInput) -> ReplayInput:
    incident = IncidentInput.model_validate_json(incident.model_dump_json())
    observations: list[Observation] = []
    gaps: list[CoverageGap] = []
    for item in sorted(incident.evidence, key=lambda value: value.id):
        if item.coverage != "complete":
            gaps.append(
                CoverageGap(source_id=item.id, modality=item.modality, reason=item.coverage)
            )
            continue
        matched = next(
            (
                (signal, match.groupdict().get("cohort"))
                for modality, signal, pattern in TEMPLATES
                if item.modality == modality and (match := re.fullmatch(pattern, item.text))
            ),
            None,
        )
        if matched is None:
            gaps.append(
                CoverageGap(source_id=item.id, modality=item.modality, reason="unsupported_payload")
            )
            continue
        signal, revision = matched
        cohort = f"revision-{revision}" if revision is not None else None
        fields: dict[str, object] = {"status": signal, "operation": f"{item.modality}.{item.id}"}
        if cohort is not None:
            fields["value"] = cohort
        result = sanitize(
            RawEvidence(
                incident.account_id,
                incident.region,
                incident.resource,
                fields,
            ),
            incident.account_id,
            incident.region,
            (incident.resource,),
        )
        if result.evidence is None:
            raise ValueError("fixture_extraction_failed")
        observations.append(
            Observation(
                source_id=item.id,
                modality=item.modality,
                provenance_group=item.provenance_group,
                occurred_at=item.occurred_at,
                observed_at=item.observed_at,
                signal=signal,
                cohort=cohort,
                evidence=result.evidence,
            )
        )
    return ReplayInput(
        **incident.model_dump(exclude={"evidence"}),
        observations=tuple(observations),
        gaps=tuple(gaps),
    )
