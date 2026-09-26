from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from incident_investigator.evaluation.canonical import MAX_BYTES, parse_json
from incident_investigator.security.sessions import AccessError, Sessions


class RuntimeSettings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", frozen=True)
    api_host: Literal["127.0.0.1"] = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1024, le=65535)
    app_mode: Literal["fixture"] = "fixture"
    development: bool = False
    data_dir: Path = Path(".data/runtime")

    @property
    def origin(self) -> str:
        return f"http://{self.api_host}:{self.api_port}"

    @property
    def origins(self) -> tuple[str, ...]:
        return (self.origin, "http://127.0.0.1:5173") if self.development else (self.origin,)


class SecurityBoundary:
    def __init__(self, app: ASGIApp, settings: RuntimeSettings, sessions: Sessions) -> None:
        self.app = app
        self.settings = settings
        self.sessions = sessions

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            await self.app(scope, receive, send)
            return
        origin: str | None = None
        started = False

        async def secured_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (b"cache-control", b"no-store"),
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                        (
                            b"content-security-policy",
                            b"default-src 'none'; script-src 'self'; "
                            b"style-src 'self'; img-src 'self'; connect-src 'self'; "
                            b"base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
                        ),
                    ]
                )
                if origin in self.settings.origins:
                    headers.extend(
                        [
                            (b"access-control-allow-origin", origin.encode()),
                            (b"vary", b"Origin"),
                            (b"access-control-allow-methods", b"GET, POST, DELETE"),
                            (b"access-control-allow-headers", b"Authorization, Content-Type"),
                        ]
                    )
                message["headers"] = headers
            await send(message)

        try:
            raw_headers = scope.get("headers", [])
            if sum(len(k) + len(v) for k, v in raw_headers) > 16_384:
                raise AccessError(431, "headers_too_large")
            headers: dict[bytes, bytes] = {}
            for key, value in raw_headers:
                if key in headers and key in (
                    b"host",
                    b"origin",
                    b"authorization",
                    b"content-length",
                    b"content-type",
                    b"content-encoding",
                    b"sec-fetch-site",
                ):
                    raise AccessError(400, "ambiguous_headers")
                headers[key] = value
            if headers.get(b"host") != f"127.0.0.1:{self.settings.api_port}".encode():
                raise AccessError(400, "invalid_host")
            origin = headers.get(b"origin", b"").decode("ascii") or None
            if origin is not None and origin not in self.settings.origins:
                raise AccessError(403, "invalid_origin")
            if headers.get(b"sec-fetch-site") == b"cross-site":
                raise AccessError(403, "cross_site_request")
            if any(k.startswith(b"x-forwarded-") or k == b"forwarded" for k in headers):
                raise AccessError(400, "proxy_headers_not_supported")
            if scope.get("query_string"):
                raise AccessError(400, "query_parameters_not_supported")
            method, path = scope["method"], scope["path"]
            if method == "OPTIONS":
                if origin is None:
                    raise AccessError(403, "invalid_origin")
                await JSONResponse({}, status_code=200)(scope, receive, secured_send)
                return
            public = (method == "POST" and path == "/api/v1/session") or (
                method in ("GET", "HEAD")
                and (path in ("/", "/api/v1/health/live") or path.startswith("/assets/"))
            )
            if not public:
                auth = headers.get(b"authorization", b"").decode("ascii")
                if not auth.startswith("Bearer ") or len(auth) > 128:
                    raise AccessError(401, "unauthorized")
                token = auth[7:]
                scope.setdefault("state", {})["session_id"] = self.sessions.authenticate(token)
            if b"content-encoding" in headers:
                raise AccessError(415, "encoded_body_not_supported")
            if b"content-length" in headers:
                length = int(headers[b"content-length"])
                if length < 0 or length > MAX_BYTES:
                    raise AccessError(413, "body_too_large")
            body = bytearray()
            async with asyncio.timeout(10):
                while True:
                    part = await receive()
                    if part["type"] == "http.disconnect":
                        return
                    body.extend(part.get("body", b""))
                    if len(body) > MAX_BYTES:
                        raise AccessError(413, "body_too_large")
                    if not part.get("more_body", False):
                        break
            if body:
                if headers.get(b"content-type", b"").split(b";")[0] != b"application/json":
                    raise AccessError(415, "json_required")
                parse_json(bytes(body))
            delivered = False

            async def replay() -> Message:
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()

            await self.app(scope, replay, secured_send)
        except AccessError as exc:
            if started:
                return
            extra = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
            await JSONResponse({"error": exc.code}, status_code=exc.status, headers=extra)(
                scope, receive, secured_send
            )
        except (ValueError, UnicodeError):
            if started:
                return
            await JSONResponse({"error": "invalid_request"}, status_code=400)(
                scope, receive, secured_send
            )
        except TimeoutError:
            if started:
                return
            await JSONResponse({"error": "request_timeout"}, status_code=408)(
                scope, receive, secured_send
            )
        except Exception:
            if not started:
                await JSONResponse({"error": "internal_error"}, status_code=500)(
                    scope, receive, secured_send
                )
