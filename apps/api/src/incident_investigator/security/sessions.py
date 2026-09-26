from __future__ import annotations

import hashlib
import secrets
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field


class AccessError(Exception):
    def __init__(self, status: int, code: str, retry_after: int | None = None) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.retry_after = retry_after


def digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


@dataclass
class Session:
    id: str
    created: float
    touched: float
    requests: deque[float] = field(default_factory=deque)
    streams: int = 0


class Sessions:
    def __init__(
        self,
        clock: Callable[[], float] = time.monotonic,
        audit: Callable[[str, str], None] | None = None,
    ) -> None:
        self.clock = clock
        self.audit = audit
        self._lock = threading.RLock()
        self._pairing: tuple[str, float] | None = None
        self._attempts: deque[float] = deque()
        self._sessions: dict[str, Session] = {}

    def _record(self, action: str, actor: str) -> None:
        if self.audit is not None:
            try:
                self.audit(action, actor)
            except Exception:
                raise AccessError(503, "audit_unavailable") from None

    def issue_pairing(self) -> str:
        secret = secrets.token_urlsafe(32)
        with self._lock:
            self._record("pairing.issue", "local-operator")
            self._pairing = (digest(secret), self.clock() + 300)
        return secret

    def _limit(self, events: deque[float], limit: int) -> None:
        now = self.clock()
        while events and events[0] <= now - 60:
            events.popleft()
        if len(events) >= limit:
            raise AccessError(429, "rate_limited", max(1, int(60 - (now - events[0])) + 1))
        events.append(now)

    def redeem(self, secret: str) -> str:
        with self._lock:
            self._limit(self._attempts, 5)
            if (
                self._pairing is None
                or self.clock() >= self._pairing[1]
                or not secrets.compare_digest(digest(secret), self._pairing[0])
            ):
                raise AccessError(401, "invalid_pairing")
            self._purge()
            if len(self._sessions) >= 32:
                raise AccessError(429, "session_limit", 60)
            identifier = secrets.token_hex(16)
            self._record("session.create", identifier)
            self._pairing = None
            token = secrets.token_urlsafe(32)
            now = self.clock()
            self._sessions[digest(token)] = Session(identifier, now, now)
            return token

    def _purge(self) -> None:
        now = self.clock()
        for key, session in tuple(self._sessions.items()):
            if now - session.created >= 28_800 or now - session.touched >= 1800:
                del self._sessions[key]

    def authenticate(self, token: str, *, touch: bool = True) -> str:
        with self._lock:
            self._purge()
            session = self._sessions.get(digest(token))
            if session is None:
                raise AccessError(401, "unauthorized")
            if touch:
                self._limit(session.requests, 120)
                session.touched = self.clock()
            return session.id

    def revoke(self, token: str) -> None:
        with self._lock:
            session = self._sessions.pop(digest(token), None)
            if session is not None:
                self._record("session.revoke", session.id)

    @contextmanager
    def stream(self, token: str) -> Iterator[None]:
        """Reserve a slot; consumers must also reauthenticate before each event."""
        with self._lock:
            self.authenticate(token, touch=False)
            session = self._sessions[digest(token)]
            if session.streams >= 2:
                raise AccessError(429, "stream_limit", 60)
            session.streams += 1
        try:
            yield
        finally:
            with self._lock:
                session.streams -= 1
