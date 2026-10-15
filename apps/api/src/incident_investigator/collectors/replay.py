"""Bounded replay of recorded SDK exchanges, not a credentialed network transport.

Elapsed times and retry delays are simulated. This validates adapter behavior without
claiming live latency, pricing, identity verification or transactional budget enforcement.
"""

from dataclasses import dataclass, field
from typing import Any, cast

from incident_investigator.collectors.contracts import (
    CollectedObservation,
    CollectionError,
    CollectionRequest,
    CollectionResult,
    Gap,
)
from incident_investigator.collectors.normalize import check_payload, normalize
from incident_investigator.collectors.requests import METRICS, Call, compile_request, query_call
from incident_investigator.evaluation.canonical import JSONValue, content_digest


@dataclass(frozen=True, repr=False)
class Exchange:
    call: Call
    response: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None
    elapsed_ms: int = 0


class RecordedTape:
    def __init__(self, exchanges: tuple[Exchange, ...]) -> None:
        if len(exchanges) > 12 or any(
            type(item.elapsed_ms) is not int or not 0 <= item.elapsed_ms <= 30_000
            for item in exchanges
        ):
            raise ValueError("invalid_recorded_tape")
        self._exchanges = exchanges
        self.position = 0

    def take(self, call: Call) -> Exchange:
        if self.position == len(self._exchanges):
            raise CollectionError("unavailable")
        exchange = self._exchanges[self.position]
        if exchange.call != call:
            raise CollectionError("scope_mismatch")
        self.position += 1
        return exchange


RETRYABLE = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "TooManyRequestsException",
        "ServiceUnavailable",
        "InternalError",
        "InternalFailure",
    }
)
DENIED = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "UnrecognizedClientException",
        "ExpiredTokenException",
    }
)


class _Replay:
    def __init__(self, request: CollectionRequest, tape: RecordedTape) -> None:
        self.request = request
        self.tape = tape
        self.calls = 0
        self.elapsed = 0

    def invoke(self, call: Call, *, reserve: int = 0) -> dict[str, Any]:
        for attempt in range(3):
            if self.calls >= self.request.max_calls - reserve:
                raise CollectionError("call_limit")
            if self.elapsed >= self.request.timeout_ms:
                raise CollectionError("deadline")
            self.calls += 1
            exchange = self.tape.take(call)
            self.elapsed += exchange.elapsed_ms
            if self.elapsed >= self.request.timeout_ms:
                raise CollectionError("deadline")
            if exchange.error_code is None:
                check_payload(exchange.response)
                if not isinstance(exchange.response, dict):
                    raise CollectionError("unsupported_payload")
                return exchange.response
            if exchange.error_code in DENIED:
                raise CollectionError("permission_denied")
            if call.method == "start_query":
                # StartQuery has no idempotency token: retrying an ambiguous failure
                # could launch another billable query with no known ID to clean up.
                raise CollectionError("unavailable")
            if exchange.error_code not in RETRYABLE:
                raise CollectionError("unavailable")
            if attempt == 2:
                raise CollectionError(
                    "throttled"
                    if "Throttl" in exchange.error_code or "TooMany" in exchange.error_code
                    else "unavailable"
                )
            # Deterministic simulated backoff; a future network transport needs jitter.
            self.elapsed += 100 * 2**attempt
        raise AssertionError("unreachable retry state")


def _merge(
    existing: list[CollectedObservation], incoming: list[CollectedObservation]
) -> list[CollectedObservation]:
    unique = {item.evidence.id: item for item in (*existing, *incoming)}
    times: dict[int, str] = {}
    for item in unique.values():
        if item.occurred_at is not None:
            if item.occurred_at in times and times[item.occurred_at] != item.evidence.id:
                raise CollectionError("unsupported_payload")
            times[item.occurred_at] = item.evidence.id
    return list(unique.values())


def replay(request: CollectionRequest, tape: RecordedTape) -> CollectionResult:
    request = CollectionRequest.model_validate_json(request.model_dump_json())
    runner = _Replay(request, tape)
    observations: list[CollectedObservation] = []
    gaps: list[Gap] = []
    initial = compile_request(request)
    active_query: str | None = None
    try:
        if request.template == "structured_logs_v1":
            started = runner.invoke(initial, reserve=2)
            active_query = started["queryId"]
            polling = query_call(active_query)
            while True:
                payload = runner.invoke(polling, reserve=1)
                state = payload["status"]
                if state == "Complete":
                    active_query = None
                    records, extra = normalize(request, payload)
                    observations = _merge([], records)
                    gaps.extend(extra)
                    break
                if state not in ("Scheduled", "Running"):
                    if state in ("Failed", "Cancelled", "Timeout"):
                        active_query = None
                    raise CollectionError("query_failed")
                # Partial query rows never become final evidence.
                runner.elapsed += 250
        else:
            seen: set[str] = set()
            call = initial
            for page in range(request.max_pages):
                payload = runner.invoke(call)
                records, extra = normalize(request, payload)
                # Check all received samples before truncation could hide a contradiction.
                observations = _merge(observations, records)
                gaps.extend(extra)
                if len(observations) > request.result_limit:
                    observations = observations[: request.result_limit]
                    gaps.append("result_limit")
                    break
                token = payload.get("NextToken")
                if token is None:
                    break
                if (
                    request.template not in METRICS
                    or not isinstance(token, str)
                    or not 0 < len(token) <= 2048
                ):
                    raise CollectionError("unsupported_payload")
                if token in seen:
                    raise CollectionError("pagination_cycle")
                seen.add(token)
                if len(observations) == request.result_limit or page + 1 == request.max_pages:
                    gaps.append("result_limit")
                    break
                call = Call(
                    initial.service, initial.method, {**initial.parameters, "NextToken": token}
                )
    except CollectionError as error:
        gaps.append(error.reason)
        if error.reason in ("scope_mismatch", "unsupported_payload", "pagination_cycle"):
            observations = []
    except (KeyError, TypeError, ValueError, IndexError, OverflowError):
        observations = []
        gaps.append("unsupported_payload")
    finally:
        if active_query is not None:
            # Cleanup consumes the reserved call and the same deadline. Failure is explicit;
            # this replay does not claim a real AWS query was cancelled.
            try:
                stopped = runner.invoke(query_call(active_query, stop=True))
                if stopped.get("success") is not True:
                    gaps.append("query_failed")
            except CollectionError as error:
                gaps.append(error.reason)
            except (ValueError, TypeError):
                gaps.append("unsupported_payload")
    if len(observations) > request.result_limit:
        observations = observations[: request.result_limit]
        gaps.append("result_limit")
    if not observations and not gaps:
        gaps.append("empty_result")
    return CollectionResult(
        request_digest=content_digest(cast(JSONValue, request.model_dump(mode="json"))),
        template=request.template,
        observations=tuple(observations),
        gaps=tuple(dict.fromkeys(gaps)),
        calls=runner.calls,
        elapsed_ms=runner.elapsed,
    )
