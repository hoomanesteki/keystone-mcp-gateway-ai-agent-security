"""What the schema says about the `args` record of the context (KS-405).

cedarpy cannot read a schema back as data, so the few facts the extractors need, the names and
types of the fields of `context.args`, are read from the schema text. The extractor tests read the
shipped file, so a change to its shape fails there and not in production.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

ArgType = Literal["Long", "String", "Bool"]
_TYPES: dict[str, ArgType] = {"Long": "Long", "String": "String", "Bool": "Bool"}

_COMMENT = re.compile(r"//[^\n]*")
_RECORD_START = re.compile(r"\bargs\s*:\s*\{")
_FIELD = re.compile(r"\s*([A-Za-z_][A-Za-z0-9_]*)(\?)?\s*:\s*([A-Za-z_][A-Za-z0-9_:]*)\s*")


@dataclass(frozen=True)
class ArgField:
    name: str
    type: ArgType
    optional: bool


def _split_top_level(body: str) -> list[str]:
    """The comma-separated parts of a record body, ignoring commas inside braces or angle brackets
    (a nested record, a `Set<...>`)."""
    parts: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(body):
        if char in "{<":
            depth += 1
        elif char in "}>":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(body[start:index])
            start = index + 1
    parts.append(body[start:])
    return parts


def _record_body(text: str) -> str | None:
    start = _RECORD_START.search(text)
    if start is None:
        return None
    depth = 1
    for index in range(start.end(), len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start.end() : index]
    return None


def args_fields(schema_text: str) -> dict[str, ArgField]:
    """The fields of the `args` record that an extractor can fill: those of type Long, String or
    Bool. An empty dict when the schema has no such record, so every extractor key is then an
    error and nothing is let through unchecked."""
    body = _record_body(_COMMENT.sub("", schema_text))
    if body is None:
        return {}
    fields: dict[str, ArgField] = {}
    for part in _split_top_level(body):
        parsed = _FIELD.fullmatch(part)
        if parsed is not None and parsed.group(3) in _TYPES:
            name = parsed.group(1)
            fields[name] = ArgField(name, _TYPES[parsed.group(3)], optional=bool(parsed.group(2)))
    return fields
