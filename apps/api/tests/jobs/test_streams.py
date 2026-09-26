import asyncio
from pathlib import Path

import pytest
from incident_investigator.jobs.api import SessionStream, events
from incident_investigator.jobs.store import JobStore
from incident_investigator.security.authority import SecurityAuthority
from incident_investigator.security.sessions import AccessError, Sessions
from starlette.requests import ClientDisconnect

from .test_store import submit


@pytest.mark.asyncio
@pytest.mark.parametrize("expire", [False, True])
async def test_stream_rechecks_logout_and_idle_expiry(tmp_path: Path, expire: bool) -> None:
    clock = [0.0]
    sessions = Sessions(lambda: clock[0])
    token = sessions.redeem(sessions.issue_pairing())
    store = JobStore(SecurityAuthority(tmp_path / "runtime"), lambda: 100)
    job = submit(store)
    generator = events(store, sessions, token, job.id, 0)
    first = await anext(generator)
    assert b"event: progress" in first and token.encode() not in first
    if expire:
        clock[0] = 1800
    else:
        sessions.revoke(token)
    with pytest.raises(StopAsyncIteration):
        await anext(generator)


@pytest.mark.asyncio
async def test_stream_slots_are_reserved_before_headers_and_released_on_disconnect(
    tmp_path: Path,
) -> None:
    sessions = Sessions()
    token = sessions.redeem(sessions.issue_pairing())
    store = JobStore(SecurityAuthority(tmp_path / "runtime"), lambda: 100)
    job = submit(store)
    scope = {"type": "http", "asgi": {"spec_version": "2.4"}}
    sent = []

    async def receive():
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)
        if message["type"] == "http.response.body":
            raise OSError("disconnected")

    with sessions.stream(token), sessions.stream(token):
        with pytest.raises(AccessError) as error:
            await SessionStream(store, sessions, token, job.id, 0)(scope, receive, send)
        assert error.value.status == 429 and sent == []
    with pytest.raises(ClientDisconnect):
        await SessionStream(store, sessions, token, job.id, 0)(scope, receive, send)
    with sessions.stream(token), sessions.stream(token):
        pass


@pytest.mark.asyncio
async def test_cancellation_releases_stream_slot(tmp_path: Path) -> None:
    sessions = Sessions()
    token = sessions.redeem(sessions.issue_pairing())
    store = JobStore(SecurityAuthority(tmp_path / "runtime"), lambda: 100)
    job = submit(store)
    started = asyncio.Event()

    async def receive():
        await asyncio.Event().wait()

    async def send(message):
        started.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(
        SessionStream(store, sessions, token, job.id, 0)(
            {"type": "http", "asgi": {"spec_version": "2.4"}}, receive, send
        )
    )
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    with sessions.stream(token), sessions.stream(token):
        pass


@pytest.mark.asyncio
@pytest.mark.parametrize("deadline", ["STREAM_SECONDS", "SEND_SECONDS"])
async def test_backpressure_cannot_keep_stream_reservations_alive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, deadline: str
) -> None:
    sessions = Sessions()
    token = sessions.redeem(sessions.issue_pairing())
    store = JobStore(SecurityAuthority(tmp_path / "runtime"), lambda: 100)
    job = submit(store)
    monkeypatch.setattr(f"incident_investigator.jobs.api.{deadline}", 0.01)

    async def receive():
        await asyncio.Event().wait()

    async def send(message):
        await asyncio.Event().wait()

    expected = TimeoutError if deadline == "STREAM_SECONDS" else ClientDisconnect
    with pytest.raises(expected):
        await SessionStream(store, sessions, token, job.id, 0)(
            {"type": "http", "asgi": {"spec_version": "2.4"}}, receive, send
        )
    with sessions.stream(token), sessions.stream(token):
        pass
