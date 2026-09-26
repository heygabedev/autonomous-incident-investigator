import asyncio
import re
import time
from collections.abc import AsyncIterator

from fastapi import APIRouter, Request
from starlette.responses import Response, StreamingResponse
from starlette.types import Message, Receive, Scope, Send

from incident_investigator.evaluation.canonical import canonical_bytes, parse_json
from incident_investigator.jobs.contracts import (
    TERMINAL,
    JobError,
    JobId,
    JobView,
    RecallReport,
    ReplayJob,
    SubmitJob,
)
from incident_investigator.jobs.service import JobService
from incident_investigator.jobs.store import JobStore
from incident_investigator.security.authority import AuditEvent
from incident_investigator.security.sessions import AccessError, Sessions


async def events(
    store: JobStore, sessions: Sessions, token: str, identifier: str, cursor: int
) -> AsyncIterator[bytes]:
    deadline = time.monotonic() + 30
    heartbeat = time.monotonic()
    while time.monotonic() < deadline:
        try:
            sessions.authenticate(token, touch=False)
            batch = await asyncio.to_thread(store.events, identifier, cursor)
            for event in batch:
                # Check again after I/O and before every event. Streams do not extend idle expiry.
                sessions.authenticate(token, touch=False)
                payload = canonical_bytes(parse_json(event.model_dump_json()))
                yield f"id: {event.sequence}\nevent: progress\ndata: ".encode() + payload + b"\n\n"
                cursor = event.sequence
            current = await asyncio.to_thread(store.get, identifier)
            if current.status in TERMINAL and not batch:
                return
            if time.monotonic() >= heartbeat:
                sessions.authenticate(token, touch=False)
                yield b": keep-alive\n\n"
                heartbeat = time.monotonic() + 5
        except AccessError:
            return
        await asyncio.sleep(0.25)


class SessionStream(StreamingResponse):
    def __init__(
        self, store: JobStore, sessions: Sessions, token: str, identifier: str, cursor: int
    ) -> None:
        super().__init__(
            events(store, sessions, token, identifier, cursor),
            media_type="text/event-stream",
            headers={"X-Accel-Buffering": "no", "X-Incident-Event-Schema": "1.0.0"},
        )
        self.sessions = sessions
        self.token = token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def bounded_send(message: Message) -> None:
            async with asyncio.timeout(5):
                await send(message)

        # Reserve before response headers; always release on disconnect or cancellation.
        with self.sessions.stream(self.token):
            await super().__call__(scope, receive, bounded_send)


def router(service: JobService | None, sessions: Sessions) -> APIRouter:
    api = APIRouter(prefix="/api/v1/investigations")

    def ready() -> JobService:
        if service is None:
            raise JobError(503, "runtime_unavailable")
        return service

    @api.post("", status_code=202)
    async def submit(request: Request) -> JobView:
        payload = SubmitJob.model_validate_json(await request.body())
        return await asyncio.to_thread(ready().submit, payload, request.state.session_id)

    @api.get("")
    def recent() -> tuple[JobView, ...]:
        return ready().store.recent()

    @api.get("/{identifier}")
    def status(identifier: JobId) -> JobView:
        return ready().store.get(identifier)

    @api.delete("/{identifier}")
    def cancel(identifier: JobId, request: Request) -> JobView:
        return ready().cancel(identifier, request.state.session_id)

    @api.post("/{identifier}/replays", status_code=202)
    async def replay(identifier: JobId, request: Request) -> JobView:
        payload = ReplayJob.model_validate_json(await request.body())
        return await asyncio.to_thread(
            ready().replay, identifier, payload, request.state.session_id
        )

    @api.post("/{identifier}/report/recall")
    async def recall(identifier: JobId, request: Request) -> JobView:
        payload = RecallReport.model_validate_json(await request.body())
        return await asyncio.to_thread(
            ready().recall, identifier, payload.reason, request.state.session_id
        )

    @api.get("/{identifier}/evidence")
    def evidence(identifier: JobId, request: Request) -> Response:
        return Response(
            ready().deliver(identifier, request.state.session_id, evidence=True),
            media_type="application/json",
        )

    @api.get("/{identifier}/report")
    def report(identifier: JobId, request: Request) -> Response:
        return Response(
            ready().deliver(identifier, request.state.session_id), media_type="application/json"
        )

    @api.get("/{identifier}/report/export")
    def export(identifier: JobId, request: Request) -> Response:
        return Response(
            ready().deliver(identifier, request.state.session_id),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="report-{identifier}.json"'},
        )

    @api.get("/{identifier}/events")
    async def stream(identifier: JobId, request: Request) -> Response:
        value = request.headers.get("last-event-id", "0")
        if not re.fullmatch(r"[0-9]{1,19}", value) or int(value) > 2**63 - 1:
            raise JobError(400, "invalid_event_cursor")
        cursor = int(value)
        store = ready().store
        await asyncio.to_thread(store.events, identifier, cursor)
        await asyncio.to_thread(
            store.authority.record,
            AuditEvent(
                actor_id=request.state.session_id,
                action="job.stream",
                decision="allow",
                reason="metadata_only",
                policy_revision=None,
                artifact_ids=(identifier,),
            ),
        )
        return SessionStream(
            store, sessions, request.headers["authorization"][7:], identifier, cursor
        )

    return api
