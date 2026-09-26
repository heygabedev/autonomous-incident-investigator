import json

import pytest
from hypothesis import given
from hypothesis import strategies as st
from incident_investigator.evaluation.canonical import (
    MAX_BYTES,
    InvalidJSON,
    canonical_bytes,
    content_digest,
    parse_json,
)


def test_jcs_utf16_order_and_number_encoding() -> None:
    # UTF-16 ordering differs from Python's Unicode code-point ordering here.
    value = {"\ue000": 4.5, "\U0001f600": 0.002, "a": -0.0}
    assert canonical_bytes(value).decode() == '{"a":0,"😀":0.002,"\ue000":4.5}'


@pytest.mark.parametrize(
    "raw",
    [
        '{"x":1,"x":2}',
        '{"x":{"a":1,"a":2}}',
        '{"x":NaN}',
        '{"x":Infinity}',
        '{"x":-Infinity}',
        '{"x":9007199254740992}',
        '{"x":9007199254740993.0}',
        '{"x":1e9999}',
        '{"x":"\\ud800"}',
        "[",
        b"\xff",
        "[[[" * 1000,
        "[" * 66 + "0" + "]" * 66,
    ],
)
def test_ambiguous_or_invalid_json_is_rejected(raw: bytes | str) -> None:
    with pytest.raises(InvalidJSON):
        parse_json(raw)


def test_size_limit_is_enforced() -> None:
    with pytest.raises(InvalidJSON):
        parse_json(b" " * (MAX_BYTES + 1))
    with pytest.raises(InvalidJSON):
        canonical_bytes("x" * MAX_BYTES)


def test_unicode_text_is_not_normalized() -> None:
    assert content_digest("é") != content_digest("e\u0301")


@given(
    st.dictionaries(
        st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=20),
        st.integers(-(2**53 - 1), 2**53 - 1),
        max_size=20,
    )
)
def test_key_order_and_json_whitespace_do_not_change_identity(value: dict[str, int]) -> None:
    reordered = dict(reversed(list(value.items())))
    assert content_digest(value) == content_digest(reordered)
    assert canonical_bytes(value) == canonical_bytes(parse_json(json.dumps(value, indent=2)))
