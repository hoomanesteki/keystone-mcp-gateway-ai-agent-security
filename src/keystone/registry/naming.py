"""Exposed tool names are `<upstream>__<tool>` (ADR-0005)."""

from __future__ import annotations

import re

SEPARATOR = "__"
_TOOL_NAME = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
_UPSTREAM_ID = re.compile(r"^[a-z][a-z0-9_]{1,30}$")


def check_upstream_id(upstream_id: str) -> None:
    """Raise ValueError unless `upstream_id` can be the first half of an exposed tool name."""
    # A trailing underscore would merge with the separator ("mail_" + "__" + "x"), and the
    # first "__" would then no longer end the id.
    if (
        not _UPSTREAM_ID.fullmatch(upstream_id)
        or SEPARATOR in upstream_id
        or upstream_id.endswith("_")
    ):
        raise ValueError(
            f"invalid upstream id {upstream_id!r}: use a lowercase letter, then 1 to 30 lowercase "
            "letters, digits or single underscores, not ending in an underscore"
        )


def make_tool_name(upstream_id: str, tool: str) -> str:
    check_upstream_id(upstream_id)
    name = f"{upstream_id}{SEPARATOR}{tool}"
    if not tool or not _TOOL_NAME.fullmatch(name):
        raise ValueError(
            f"invalid tool name {name!r}: letters, digits, '_' and '-' only, 1 to 64 characters"
        )
    return name


def split_tool_name(name: str) -> tuple[str, str]:
    upstream_id, separator, tool = name.partition(SEPARATOR)
    if not separator or not tool:
        raise ValueError(f"invalid tool name {name!r}: expected '<upstream>__<tool>'")
    try:
        check_upstream_id(upstream_id)
    except ValueError as exc:
        raise ValueError(f"invalid tool name {name!r}: {exc}") from exc
    return upstream_id, tool
