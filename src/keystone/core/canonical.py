"""Canonical JSON, so the same data always hashes to the same digest."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel


def _default(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            # A naive time is ambiguous, so two hashes of one moment could differ.
            raise ValueError("datetime has no timezone")
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, set | frozenset):
        return sorted(value)
    if isinstance(value, BaseModel):
        return value.model_dump()
    raise TypeError(f"{type(value).__name__} is not canonical JSON")


def canonical_json(obj: Any) -> bytes:
    """Sorted keys, no whitespace, UTF-8, datetimes as ISO 8601 UTC with a trailing Z."""
    text = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=_default,
    )
    return text.encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
