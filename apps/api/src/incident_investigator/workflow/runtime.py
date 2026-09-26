"""Offline attempt lifecycle, with content-pinned code, policy and installed dependencies."""

import hashlib
import sys
import time
import uuid
from collections.abc import Callable
from importlib.metadata import distributions
from pathlib import Path

from incident_investigator.evaluation.canonical import JSONValue, content_digest, parse_json
from incident_investigator.evaluation.golden import IncidentInput
from incident_investigator.security.authority import SecurityAuthority
from incident_investigator.security.policy import ActionRequest, SecurityContext, SecurityPolicy
from incident_investigator.workflow.checkpoints import CheckpointGuard, CheckpointStore
from incident_investigator.workflow.contracts import ReplayInput, RunPin, RunState, Stage
from incident_investigator.workflow.graph import build_graph, invoke, make_report, validate_state
from incident_investigator.workflow.replay import prepare


def runtime_digest() -> str:
    root = Path(__file__).resolve().parents[1]
    files: dict[str, JSONValue] = {}
    for path in sorted(root.rglob("*.py")):
        # Normalize checkout line endings; identities must agree across OSes.
        files[path.relative_to(root).as_posix()] = hashlib.sha256(
            path.read_text(encoding="utf-8").encode("utf-8")
        ).hexdigest()
    dependencies: dict[str, JSONValue] = {
        distribution.metadata["Name"].lower().replace("_", "-"): distribution.version
        for distribution in distributions()
    }
    return content_digest(
        {
            "files": files,
            "dependencies": dependencies,
            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        }
    )


def offline_pin(policy: SecurityPolicy) -> RunPin:
    graph = runtime_digest()
    policy_digest = content_digest(parse_json(policy.model_dump_json()))
    candidate = content_digest(
        {
            "graph": graph,
            "policy": policy_digest,
            "mode": "fixture",
            "history": "disabled",
            "models": "disabled",
        }
    )
    suffix = candidate[7:31]
    return RunPin(
        release_id=f"offline-{suffix}",
        candidate_id=f"fixture-{suffix}",
        candidate_digest=candidate,
        graph_digest=graph,
        policy_digest=policy_digest,
    )


class OfflineRuntime:
    def __init__(
        self,
        authority: SecurityAuthority,
        clock: Callable[[], int] | None = None,
        guard: CheckpointGuard | None = None,
    ) -> None:
        self.authority = authority
        self.store = CheckpointStore(authority)
        self.clock = clock or (lambda: int(time.time()))
        self.guard = guard

    def start(
        self,
        incident: IncidentInput,
        *,
        attempt_id: str | None = None,
        round_limit: int = 2,
        stop_after: Stage | None = None,
    ) -> RunState:
        state, policy = self.initialize(prepare(incident), attempt_id, round_limit)
        return self.begin(state, policy, stop_after=stop_after)

    def begin(
        self, state: RunState, policy: SecurityPolicy, *, stop_after: Stage | None = None
    ) -> RunState:
        if state.pin != offline_pin(policy):
            raise ValueError("checkpoint_runtime_mismatch")
        self.store.save(state, policy, expected=None, now=self.clock(), guard=self.guard)
        return self._execute(state, policy, stop_after)

    def initialize(
        self, ready: ReplayInput, attempt_id: str | None = None, round_limit: int = 2
    ) -> tuple[RunState, SecurityPolicy]:
        ready = ReplayInput.model_validate_json(ready.model_dump_json())
        policy = SecurityPolicy(
            id="offline-investigation-v1",
            revision=1,
            expires_at=self.clock() + 28_800,
            account_id=ready.account_id,
            region=ready.region,
            resources=(ready.resource,),
            operations=("fixture.read", "report.publish"),
            templates=("offline-investigation-v1",),
            result_limit=100,
            remaining_microdollars=0,
        )
        state = RunState(
            attempt_id=attempt_id or uuid.uuid4().hex,
            pin=offline_pin(policy),
            input_digest=content_digest(parse_json(ready.model_dump_json())),
            incident=ready,
            round_limit=round_limit,
        )
        return state, policy

    def resume(self, attempt_id: str, *, stop_after: Stage | None = None) -> RunState:
        state, policy = self.store.load(attempt_id)
        if state.pin != offline_pin(policy):
            raise ValueError("checkpoint_runtime_mismatch")
        return self._execute(state, policy, stop_after)

    def _execute(
        self, state: RunState, policy: SecurityPolicy, stop_after: Stage | None
    ) -> RunState:
        validate_state(state, state.pin)
        context = SecurityContext(
            actor_id="local-operator",
            candidate_id=state.pin.candidate_id,
            policy_id=policy.id,
            account_id=state.incident.account_id,
            region=state.incident.region,
        )
        broker = self.authority.broker(policy, self.clock)
        previous = [state]

        def checkpoint(next_state: RunState) -> None:
            self.store.save(
                next_state, policy, expected=previous[0], now=self.clock(), guard=self.guard
            )
            previous[0] = next_state

        result = invoke(
            build_graph(state.pin, context, policy, broker, checkpoint, stop_after), state
        )
        if result.report is not None:
            # Cached results are not an authorization bypass after revocation.
            request = ActionRequest(
                operation="report.publish",
                account_id=context.account_id,
                region=context.region,
                resource=state.incident.resource,
                template="offline-investigation-v1",
                result_limit=100,
                cost_microdollars=0,
            )
            broker.dispatch(context, request, policy, lambda _: make_report(result))
        return result
