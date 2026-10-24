"""Exposed tool names are `<upstream>__<tool>` (ADR-0005)."""

from __future__ import annotations

import re

from keystone.core.types import ToolRef

SEPARATOR = "__"
_TOOL_NAME = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
_UPSTREAM_ID = re.compile(r"^[a-z][a-z0-9_]{1,30}$")

# The upstream that Keystone itself is: keystone__await_approval and keystone__whoami (KS-603).
# No configured upstream may have this id, so a tool whose upstream is this one can only be one of
# Keystone's own, and the pipeline can treat it as such without asking the registry.
VIRTUAL_UPSTREAM = "keystone"
# The pseudo-upstreams that hold the provider keys of the LLM proxy as static credentials in the
# vault (KS-806). They are rows so that a credential has an upstream to belong to, and they are
# never synced, probed or listed: no tool is called by their names.
LLM_UPSTREAM_IDS = frozenset({"llm_anthropic", "llm_openai"})
RESERVED_UPSTREAM_IDS = frozenset({VIRTUAL_UPSTREAM, *LLM_UPSTREAM_IDS})


# The upstreams that Keystone runs itself, named in the config with `transport: builtin` (KS-802).
# Unlike `keystone`, they are upstreams in every other way: a row, tools in the registry, and a
# call through the whole pipeline.
BUILTIN_UPSTREAM_IDS = frozenset({"sandbox"})


def is_reserved(upstream_id: str) -> bool:
    return upstream_id in RESERVED_UPSTREAM_IDS


def is_virtual(tool: ToolRef) -> bool:
    """True for a tool that Keystone serves itself. The upstream id alone decides it, and the
    config loader, the CLI and the registry keep that id out of every upstream."""
    return tool.upstream_id == VIRTUAL_UPSTREAM


def check_upstream_id(upstream_id: str) -> None:
    """Raise ValueError unless `upstream_id` can be the first half of an exposed tool name."""
    if upstream_id in LLM_UPSTREAM_IDS:
        raise ValueError(
            f"invalid upstream id {upstream_id!r}: it is reserved for the provider keys of the "
            "LLM proxy"
        )
    if is_reserved(upstream_id):
        raise ValueError(
            f"invalid upstream id {upstream_id!r}: it is reserved for Keystone's own tools "
            f"({VIRTUAL_UPSTREAM}{SEPARATOR}await_approval and {VIRTUAL_UPSTREAM}{SEPARATOR}whoami)"
        )
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
