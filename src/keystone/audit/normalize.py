"""Text and JSON in the form Postgres returns unchanged (KS-501, ADR-0009).

The audit writer hashes what it stores, and verification hashes what a SELECT returns, so a value
must not change on the way through the database. `text` and `jsonb` cannot hold a NUL character,
and jsonb keeps a number as a `numeric`: it prints it without an exponent, which turns a float
such as 1e22 into an integer, and it has no negative zero.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from decimal import Decimal
from typing import Any

MAX_JSON_DEPTH = 32
TRUNCATED = "[truncated]"
NUL_TEXT = "\\u0000"


def clean_text(text: str) -> str:
    """Text Postgres can store: no NUL character, and no lone surrogate (which is not UTF-8)."""
    if "\x00" in text:
        text = text.replace("\x00", NUL_TEXT)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = text.encode("utf-8", "replace").decode("utf-8")
    return text


def stable_float(value: float) -> int | float | str:
    """A float in the form jsonb returns unchanged. Postgres prints a numeric without an
    exponent, so a float whose digits have no fraction (1e22) is read back as an integer."""
    if not math.isfinite(value):
        return str(value)
    if value == 0:
        return 0.0  # jsonb has no negative zero
    plain = format(Decimal(repr(value)), "f")
    return float(plain) if "." in plain else int(plain)


def stable_json(value: Any, _depth: int = 0) -> Any:
    """`value` as JSON that survives a round trip through jsonb: strings Postgres can store,
    numbers in the form it returns, keys as strings. Anything that is not JSON becomes its text,
    and nesting deeper than MAX_JSON_DEPTH is cut."""
    if _depth > MAX_JSON_DEPTH:
        return TRUNCATED
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        return stable_float(value)
    if isinstance(value, str):
        return clean_text(value)
    if isinstance(value, Mapping):
        return {clean_text(str(k)): stable_json(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [stable_json(item, _depth + 1) for item in value]
    return clean_text(str(value))
