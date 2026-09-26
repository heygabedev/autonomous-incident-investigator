"""Append-only local metadata storage. Not a private-data security boundary."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from pydantic import ValidationError

from incident_investigator.evaluation.artifacts import ArtifactEnvelope, parse_envelope
from incident_investigator.evaluation.models import ArtifactRef, Kind


class RegistryError(ValueError):
    """Safe public registry error without stored content."""


class IdentityConflict(RegistryError):
    pass


class IntegrityError(RegistryError):
    pass


class NotFound(RegistryError):
    pass


class SQLiteRegistry:
    def __init__(self, path: Path) -> None:
        self.path = path.resolve()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path, timeout=10)) as connection, connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS artifacts ("
                "digest TEXT PRIMARY KEY, kind TEXT NOT NULL, id TEXT NOT NULL, "
                "version TEXT NOT NULL, envelope BLOB NOT NULL, "
                "UNIQUE(kind, id, version))"
            )

    def _connect(self, *, writable: bool = False) -> sqlite3.Connection:
        if not self.path.is_file():
            raise NotFound("registry does not exist; initialize it explicitly")
        mode = "rw" if writable else "ro"
        return sqlite3.connect(f"{self.path.as_uri()}?mode={mode}", uri=True, timeout=10)

    @staticmethod
    def _decode(row: tuple[str, str, str, str, bytes]) -> ArtifactEnvelope:
        try:
            envelope = parse_envelope(row[4])
        except (ValueError, ValidationError) as exc:
            raise IntegrityError("stored artifact failed integrity validation") from exc
        reference = envelope.reference()
        if (reference.digest, reference.kind, reference.id, reference.version) != row[:4]:
            raise IntegrityError("stored identity does not match its envelope")
        return envelope

    def put(self, envelope: ArtifactEnvelope) -> ArtifactRef:
        # Revalidate even callers that bypassed Pydantic construction.
        verified = parse_envelope(envelope.to_bytes())
        ref = verified.reference()
        with closing(self._connect(writable=True)) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT digest, kind, id, version, envelope FROM artifacts "
                "WHERE digest = ? OR (kind = ? AND id = ? AND version = ?)",
                (ref.digest, ref.kind, ref.id, ref.version),
            ).fetchall()
            if rows:
                for row in rows:
                    if self._decode(row) != verified:
                        raise IdentityConflict("identity already has different content")
                return ref
            connection.execute(
                "INSERT INTO artifacts VALUES (?, ?, ?, ?, ?)",
                (ref.digest, ref.kind, ref.id, ref.version, verified.to_bytes()),
            )
        return ref

    def get(self, digest: str) -> ArtifactEnvelope:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT digest, kind, id, version, envelope FROM artifacts WHERE digest = ?",
                (digest,),
            ).fetchone()
        if row is None:
            raise NotFound("artifact not found")
        return self._decode(row)

    def resolve(self, reference: ArtifactRef) -> ArtifactEnvelope:
        envelope = self.get(reference.digest)
        if envelope.reference() != reference:
            raise IntegrityError("reference identity does not match stored artifact")
        return envelope

    def list_kind(self, kind: Kind) -> tuple[ArtifactEnvelope, ...]:
        with closing(self._connect()) as connection:
            # Validate every row, including its kind, before selecting events. Otherwise
            # a damaged kind column could hide a current invalidation from this reader.
            rows = connection.execute(
                "SELECT digest, kind, id, version, envelope FROM artifacts ORDER BY digest"
            ).fetchall()
        envelopes = tuple(self._decode(row) for row in rows)
        return tuple(item for item in envelopes if item.payload.kind == kind)
