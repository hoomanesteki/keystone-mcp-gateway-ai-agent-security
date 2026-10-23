"""Argument extractors (KS-405): a few arguments of a call, as typed facts a policy may read.

A tool's config says which arguments matter and how to read them:

    send_email: {extract: {recipient_domain: "$.to | domain"}}
    transfer:   {extract: {amount: "$.amount | cents"}}

The key is a field of the schema's `args` record (`context.args.amount` in a policy). The value is
a path into the call's arguments, then pipes:

    path    `$.a`, `$.a.b`, `$.a[0]`, in any mix
    int     a number, or text that is a number, with the fraction cut off (toward zero)
    cents   the same, times 100, rounded half up: money without a fraction
    domain  the domain of one plain email address, in lower case
    lower   the text in lower case
    len     the length of a text or a list

A path that is not there, or a value a pipe cannot use, leaves the key out and says why at debug
level (never the value). A policy must therefore ask `context.args has amount` before it reads
the field, and the default policies treat a missing field as "do not know", not as "fine".

Two choices keep a rule from being skipped by accident. A number beyond the range of a Cedar Long
is capped at the range, so "approve transfers over 500" still sees a transfer of 10^30. And
`domain` accepts one plain address only: `a@evil.test,b@acme.test` has no domain, so it cannot pass
for `acme.test`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import ROUND_DOWN, ROUND_HALF_UP, Decimal, InvalidOperation
from functools import lru_cache
from typing import Any, Literal

import structlog

from keystone.policy.schema_info import ArgField

log = structlog.get_logger()

MAX_LONG = 2**63 - 1
MIN_LONG = -(2**63)
Value = int | str | bool
Pipe = Literal["int", "cents", "domain", "lower", "len"]
PIPES: tuple[Pipe, ...] = ("int", "cents", "domain", "lower", "len")
Kind = Literal["Long", "String", "any"]
# What each pipe produces. A spec with no pipe produces whatever the argument is.
_PRODUCES: dict[str, Kind] = {
    "int": "Long",
    "cents": "Long",
    "domain": "String",
    "lower": "String",
    "len": "Long",
}

_NAME = r"[A-Za-z_][A-Za-z0-9_-]*"
_STEP = re.compile(rf"\.({_NAME})|\[(\d+)\]")
_ADDRESS_DOMAIN = re.compile(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?")
# Characters that make a string something other than one plain address.
_NOT_PLAIN = re.compile(r"[\s,;<>()\[\]\"\\]")
_CENT = Decimal(100)


class ExtractorError(ValueError):
    """A spec that is not in the language."""


class _Skip(Exception):
    """The key is left out. `why` is for the debug log."""

    def __init__(self, why: str) -> None:
        super().__init__(why)
        self.why = why


@dataclass(frozen=True)
class Extractor:
    path: tuple[str | int, ...]
    pipes: tuple[Pipe, ...]

    @property
    def produces(self) -> Kind:
        """The type of what this gives, when it is known without seeing an argument."""
        return _PRODUCES[self.pipes[-1]] if self.pipes else "any"


@lru_cache(maxsize=512)
def parse_extractor(spec: str) -> Extractor:
    """Read a spec. Raises ExtractorError for anything outside the language, naming the problem."""
    path_text, *pipe_texts = (part.strip() for part in spec.split("|"))
    if not path_text.startswith("$"):
        raise ExtractorError("a path starts with $")
    rest = path_text[1:]
    path: list[str | int] = []
    position = 0
    while position < len(rest):
        step = _STEP.match(rest, position)
        if step is None:
            raise ExtractorError(f"cannot read the path at {rest[position:]!r}")
        path.append(step.group(1) if step.group(1) is not None else int(step.group(2)))
        position = step.end()
    if not path:
        raise ExtractorError("the path names nothing; use $.name")
    pipes: list[Pipe] = []
    for text in pipe_texts:
        if text not in PIPES:
            shown = text or "(nothing)"
            raise ExtractorError(f"unknown pipe {shown}; the pipes are {', '.join(PIPES)}")
        pipes.append(text)
    return Extractor(tuple(path), tuple(pipes))


def _walk(arguments: Any, path: tuple[str | int, ...]) -> Any:
    current = arguments
    for step in path:
        if isinstance(step, str):
            if not isinstance(current, dict) or step not in current:
                raise _Skip("no such path")
            current = current[step]
        else:
            if not isinstance(current, list) or step >= len(current):
                raise _Skip("no such path")
            current = current[step]
    return current


def _decimal(value: Any) -> Decimal:
    if isinstance(value, bool):
        raise _Skip("not a number")
    try:
        if isinstance(value, int):
            return Decimal(value)
        if isinstance(value, float):
            return Decimal(repr(value))  # the shortest text of the float, not its binary digits
        if isinstance(value, str):
            return Decimal(value.strip())
    except InvalidOperation:
        raise _Skip("not a number") from None
    raise _Skip("not a number")


def _long(number: Decimal, factor: Decimal, rounding: str) -> int:
    """`number` times `factor`, rounded to a whole number and capped to the range of a Long."""
    if number.is_nan():
        raise _Skip("not a number")
    limit = Decimal(MAX_LONG) / factor
    if number >= limit:
        return MAX_LONG
    if number <= -limit:
        return MIN_LONG
    whole = (number * factor).quantize(Decimal(1), rounding=rounding)
    return max(MIN_LONG, min(MAX_LONG, int(whole)))


def _domain(value: Any) -> str:
    if not isinstance(value, str):
        raise _Skip("not text")
    text = value.strip()
    if text.count("@") != 1 or _NOT_PLAIN.search(text):
        raise _Skip("not one plain address")
    local, _, domain = text.partition("@")
    domain = domain.lower()
    if not local or not _ADDRESS_DOMAIN.fullmatch(domain):
        raise _Skip("not one plain address")
    return domain


def _pipe(name: Pipe, value: Any) -> Any:
    if name == "int":
        return _long(_decimal(value), Decimal(1), ROUND_DOWN)
    if name == "cents":
        return _long(_decimal(value), _CENT, ROUND_HALF_UP)
    if name == "domain":
        return _domain(value)
    if name == "lower":
        if not isinstance(value, str):
            raise _Skip("not text")
        return value.lower()
    if isinstance(value, str | list):
        return len(value)
    raise _Skip("not text or a list")


def _run(arguments: Mapping[str, Any], extractor: Extractor) -> Value:
    value = _walk(arguments, extractor.path)
    for name in extractor.pipes:
        value = _pipe(name, value)
    if isinstance(value, bool | str):
        return value
    if isinstance(value, int):
        return max(MIN_LONG, min(MAX_LONG, value))
    raise _Skip("not a number, text or yes/no")


def extract(arguments: Mapping[str, Any], spec: Mapping[str, str]) -> dict[str, Value]:
    """The facts `spec` asks for, from a call's arguments. A key that cannot be filled is left
    out. `spec` was checked at startup (`check_extractors`); a spec that fails to parse here is a
    stale one and is left out too, with a warning."""
    found: dict[str, Value] = {}
    for key, text in spec.items():
        try:
            found[key] = _run(arguments, parse_extractor(text))
        except _Skip as skipped:
            log.debug("extractor_skipped", key=key, why=skipped.why)
        except ExtractorError as error:
            log.warning("extractor_unusable", key=key, why=str(error))
    return found


def check_extractors(spec: Mapping[str, str], fields: Mapping[str, ArgField]) -> list[str]:
    """What is wrong with a tool's `extract` config, one sentence per problem: a key that is not a
    field of the schema's `args` record, a spec outside the language, or a spec whose result is
    the wrong type for its field."""
    problems = []
    for key, text in spec.items():
        field = fields.get(key)
        if field is None:
            known = ", ".join(sorted(fields)) or "none"
            problems.append(
                f"extract key {key!r} is not an argument the policies can read "
                f"(the schema's args has: {known})"
            )
            continue
        try:
            produces = parse_extractor(text).produces
        except ExtractorError as error:
            problems.append(f"extract key {key!r}: {error}")
            continue
        if produces == "String" and field.type != "String":
            problems.append(
                f"extract key {key!r} produces text but the schema's {key} is a {field.type}"
            )
        elif produces == "Long" and field.type != "Long":
            problems.append(
                f"extract key {key!r} produces a number but the schema's {key} is a {field.type}"
            )
    return problems
