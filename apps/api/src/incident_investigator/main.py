from __future__ import annotations

import sqlite3
import subprocess
import sys
import threading
from pathlib import Path
from typing import Annotated

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import Field
from starlette.staticfiles import StaticFiles

from incident_investigator import __version__
from incident_investigator.evaluation.models import Contract
from incident_investigator.security.authority import AuditEvent, SecurityAuthority
from incident_investigator.security.http import RuntimeSettings, SecurityBoundary
from incident_investigator.security.sessions import AccessError, Sessions


class PairingRequest(Contract):
    secret: Annotated[str, Field(min_length=32, max_length=128, repr=False)]


def create_app(
    settings: RuntimeSettings | None = None,
    sessions: Sessions | None = None,
    ui_directory: Path | None = None,
    authority: SecurityAuthority | None = None,
) -> FastAPI:
    settings = settings or RuntimeSettings()
    sessions = sessions or Sessions()
    app = FastAPI(
        title="Autonomous Incident Investigator",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(SecurityBoundary, settings=settings, sessions=sessions)
    # Future operation handlers must use this authority's broker; no API exposes
    # containment changes, evaluation labels, or operating-system paths.
    app.state.security_authority = authority

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse({"error": "invalid_request"}, status_code=422)

    @app.post("/api/v1/session")
    async def pair(payload: PairingRequest) -> dict[str, str]:
        return {"token": sessions.redeem(payload.secret), "token_type": "Bearer"}

    @app.get("/api/v1/session")
    async def session(request: Request) -> dict[str, str]:
        return {"session_id": request.state.session_id, "version": __version__}

    @app.delete("/api/v1/session")
    async def logout(request: Request) -> dict[str, str]:
        sessions.revoke(request.headers["authorization"][7:])
        return {"status": "signed_out"}

    @app.get("/api/v1/health/live", tags=["health"])
    async def liveness() -> dict[str, str]:
        return {"status": "ok"}

    if ui_directory is not None:
        root = ui_directory.resolve(strict=True)
        if not (root / "index.html").is_file() or not (root / "assets").is_dir():
            raise ValueError("UI build is missing")
        if any(path.is_symlink() or path.is_junction() for path in root.rglob("*")):
            raise ValueError("UI build must not contain links")
        app.mount("/assets", StaticFiles(directory=root / "assets"), name="assets")

        @app.get("/")
        async def index() -> FileResponse:
            return FileResponse(root / "index.html")

    return app


def run() -> None:
    try:
        _run()
    except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError):
        print(
            "Startup refused: invalid configuration or unavailable private storage.",
            file=sys.stderr,
        )
        raise SystemExit(2) from None


def _run() -> None:
    settings = RuntimeSettings()
    authority = SecurityAuthority(settings.data_dir)

    def session_audit(action: str, actor: str) -> None:
        authority.record(
            AuditEvent(
                actor_id=actor,
                action=action,
                decision="allow",
                reason="local_session",
                policy_revision=authority.read().revision,
            )
        )

    sessions = Sessions(audit=session_audit)
    ui = Path("apps/web/dist")
    application = create_app(settings, sessions, ui if ui.is_dir() else None, authority)

    def terminal() -> None:
        def issue() -> None:
            try:
                print("Pairing code (expires in five minutes):", sessions.issue_pairing())
            except AccessError:
                print("Pairing unavailable: security audit storage is unavailable.")

        issue()
        print("Type 'pair' to issue a new code. Codes are not recorded in application logs.")
        for command in sys.stdin:
            if command.strip() == "pair":
                issue()

    if sys.stdin.isatty() and sys.stdout.isatty():
        threading.Thread(target=terminal, daemon=True).start()
    uvicorn.run(
        application,
        host=settings.api_host,
        port=settings.api_port,
        reload=False,
        access_log=False,
        proxy_headers=False,
        server_header=False,
        limit_concurrency=64,
        timeout_keep_alive=5,
    )
