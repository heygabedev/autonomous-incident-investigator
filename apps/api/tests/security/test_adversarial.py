import asyncio
import io
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from hypothesis import given
from hypothesis import strategies as st
from incident_investigator import main
from incident_investigator.security.evidence import RawEvidence, evidence_bytes, sanitize
from incident_investigator.security.http import RuntimeSettings, SecurityBoundary
from incident_investigator.security.sessions import AccessError, Sessions


@given(st.text(max_size=200))
def test_secrets_embedded_in_structured_payload_never_survive(prefix: str) -> None:
    seed = "password=fixture-secret"
    result = sanitize(
        RawEvidence("000000000000", "eu-central-1", "fixture-1", {"status": prefix + " " + seed}),
        "000000000000",
        "eu-central-1",
        ("fixture-1",),
    )
    if result.evidence is not None:
        assert seed.encode() not in evidence_bytes(
            (result.evidence,), "000000000000", "eu-central-1", ("fixture-1",)
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        AccessError(401, "unauthorized"),
        ValueError("secret"),
        TimeoutError(),
        RuntimeError("secret"),
    ],
)
async def test_started_responses_terminate_without_second_status_or_secret(
    error: Exception,
) -> None:
    messages: list[dict[str, Any]] = []

    async def application(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"safe", "more_body": True})
        raise error

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b""}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    boundary = SecurityBoundary(application, RuntimeSettings(), Sessions())
    await boundary(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/health/live",
            "headers": [(b"host", b"127.0.0.1:8000")],
        },
        receive,
        send,
    )
    assert sum(message["type"] == "http.response.start" for message in messages) == 1
    assert messages[-1]["more_body"] is False
    assert "secret" not in repr(messages)


@pytest.mark.asyncio
async def test_chunked_limit_stops_reading_and_cancellation_does_not_dispatch() -> None:
    called = False

    async def application(scope: Any, receive: Any, send: Any) -> None:
        nonlocal called
        called = True

    messages: list[dict[str, Any]] = []
    received = 0

    async def receive() -> dict[str, Any]:
        nonlocal received
        received += 1
        return {"type": "http.request", "body": b"x" * 600_000, "more_body": True}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    boundary = SecurityBoundary(application, RuntimeSettings(), Sessions())
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/session",
        "headers": [(b"host", b"127.0.0.1:8000"), (b"content-type", b"application/json")],
    }
    await boundary(scope, receive, send)
    assert received == 2 and not called
    assert messages[0]["status"] == 413

    async def cancelled() -> dict[str, Any]:
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await boundary(scope, cancelled, send)
    assert not called


def test_entrypoint_is_loopback_and_noninteractive_never_prints_pairing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = Mock()
    output = io.StringIO()
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "private"))
    monkeypatch.setattr(main.sys, "stdin", io.StringIO())
    monkeypatch.setattr(main.sys, "stdout", output)
    monkeypatch.setattr(main.uvicorn, "run", runner)
    main.run()
    options = runner.call_args.kwargs
    assert options["host"] == "127.0.0.1"
    assert not options["proxy_headers"] and not options["access_log"]
    assert options["limit_concurrency"] == 64
    assert output.getvalue() == ""


def test_startup_configuration_errors_do_not_echo_values(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("API_HOST", "private-secret-not-a-host")
    with pytest.raises(SystemExit) as error:
        main.run()
    assert error.value.code == 2
    assert "private-secret" not in capsys.readouterr().err
