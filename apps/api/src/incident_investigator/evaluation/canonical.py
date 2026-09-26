"""Bounded strict JSON parsing and versioned RFC 8785 artifact identities."""

from __future__ import annotations

import hashlib
import json
import math
from decimal import Decimal
from typing import cast

import rfc8785

type JSONValue = bool | int | float | str | list[JSONValue] | dict[str, JSONValue] | None

MAX_BYTES = 1_048_576
MAX_DEPTH = 64
MAX_INTEGER = (1 << 53) - 1


class InvalidJSON(ValueError):
    """Invalid or non-interoperable artifact JSON, without sensitive input in errors."""


def _object(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
    result: dict[str, JSONValue] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidJSON("duplicate JSON key")
        result[key] = value
    return result


def _integer(value: str) -> int:
    result = int(value)
    if abs(result) > MAX_INTEGER:
        raise InvalidJSON("integer exceeds interoperable range")
    return result


def _float(value: str) -> float:
    decimal = Decimal(value)
    if decimal == decimal.to_integral_value() and abs(decimal) > MAX_INTEGER:
        raise InvalidJSON("integer-valued number exceeds interoperable range")
    result = float(value)
    if not math.isfinite(result):
        raise InvalidJSON("non-finite number")
    return result


def _constant(value: str) -> None:
    raise InvalidJSON("non-finite number")


def _validate(value: JSONValue, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise InvalidJSON("JSON nesting limit exceeded")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise InvalidJSON("object keys must be strings")
            _validate(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate(child, depth + 1)
    elif isinstance(value, bool) or value is None or isinstance(value, str):
        return
    elif isinstance(value, int):
        if abs(value) > MAX_INTEGER:
            raise InvalidJSON("integer exceeds interoperable range")
    elif isinstance(value, float):
        if not math.isfinite(value) or (value.is_integer() and abs(value) > MAX_INTEGER):
            raise InvalidJSON("number exceeds interoperable range")
    else:
        raise InvalidJSON("unsupported JSON value")


def canonical_bytes(value: JSONValue) -> bytes:
    """Encode JCS using the project's bounded, safe-number JSON profile."""
    try:
        _validate(value)
        result = rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, UnicodeError, RecursionError) as exc:
        raise InvalidJSON("cannot canonicalize artifact JSON") from exc
    if len(result) > MAX_BYTES:
        raise InvalidJSON("artifact exceeds size limit")
    return result


def parse_json(raw: bytes | str) -> JSONValue:
    """Reject ambiguous input before schema validation can discard information."""
    try:
        data = raw.encode("utf-8") if isinstance(raw, str) else raw
        if len(data) > MAX_BYTES:
            raise InvalidJSON("artifact exceeds size limit")
        value = cast(
            JSONValue,
            json.loads(
                data.decode("utf-8"),
                object_pairs_hook=_object,
                parse_int=_integer,
                parse_float=_float,
                parse_constant=_constant,
            ),
        )
        canonical_bytes(value)
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidJSON("invalid artifact JSON") from exc


def content_digest(value: JSONValue) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()
